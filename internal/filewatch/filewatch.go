// Package filewatch implements the v0.3 Runtime Sensor · File Plane MVP
// (ARCHITECTURE.md 10.1): best-effort, record-only file mutation tracking
// for the session's working directory. Like Process Plane, this never
// blocks anything and never reads file content — only paths and
// operations (ARCHITECTURE.md 0.8/0.9's "no raw secrets/content"
// invariant applies here too: a file's content could be anything,
// including the exact secrets the Egress Sensor exists to catch).
//
// Uses fsnotify (kqueue-backed on macOS, no cgo) rather than
// polling — unlike process enumeration, there's no equivalent to `ps` for
// "list recent filesystem changes", so a kernel-notified watch is both
// simpler and more complete than polling mtimes would be.
//
// fsnotify doesn't support recursive watching natively; this package
// walks the tree once at startup and adds a watch per directory, then adds
// new watches for directories created during the session. Several safety
// valves keep this from becoming a liability during an active coding
// session (compilers, package managers, and editors can generate a lot of
// churn, and a mid-sized repo can have far more directories than an OS's
// default file-descriptor limit allows):
//   - a fixed exclude-list of common noisy directories (.git, node_modules,
//     vendor, build output, ...) skipped entirely, not even watched
//   - the process's open-file soft limit is raised at startup, and the
//     number of directories watched is capped based on the limit actually
//     achieved — if a repo has more directories than fit, watching
//     degrades to just the root (non-recursive) rather than silently
//     leaving an unpredictable subset unwatched or, worse, exhausting file
//     descriptors that the Egress Sensor's own listening socket needs too
//     (found in the v0.3 security review: this process's proxy and file
//     watcher share one fd table, so fd exhaustion here could take the
//     network proxy down, not just File Plane)
//   - a hard cap on total events recorded per session; once hit, watching
//     continues (so we don't lose the "it's still running" signal) but
//     new events are silently dropped rather than let the database or
//     memory grow without bound
package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/fsnotify/fsnotify"

	"github.com/wang110696/Leash/internal/store"
)

// MaxEventsPerSession caps how many file_mutation events a single session
// will record, independent of how long it runs or how much churn happens.
// A var (not a const) so tests can lower it to exercise the cap without
// generating 5000 real filesystem events.
var MaxEventsPerSession = 5000

// MaxWatchedDirs caps how many directories New will place a watch on
// before giving up on full recursive coverage and falling back to
// watching just root. A var for the same reason as MaxEventsPerSession —
// tests need to exercise the degrade path without creating thousands of
// real directories. The effective cap used at runtime is also bounded by
// how many file descriptors are actually available (see raiseFDLimit).
var MaxWatchedDirs = 2000

// fdHeadroom is how many file descriptors New() deliberately leaves
// unused by the directory watch budget, reserved for the rest of the
// process's needs (stdio, the SQLite connection, the Egress Sensor's
// listening socket and in-flight connections).
const fdHeadroom = 64

// hardFDCap is a concrete ceiling used when the OS reports an
// effectively-unlimited hard limit (macOS commonly does) that the kernel
// will still refuse in practice — trusting a real, moderate number is
// more reliable than trusting the reported ceiling.
const hardFDCap = 10240

// excludedDirNames are skipped entirely — not watched, not descended into.
// This is a fixed list, not configurable in v0.3 (ARCHITECTURE.md's
// "don't over-engineer v0.1/v0.2/v0.3" lesson applies equally here: add
// policy-driven exclude lists only once someone actually needs one).
var excludedDirNames = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"target":       true,
	".leash":       true,
}

// Watcher tracks file mutations under root.
type Watcher struct {
	sessionID string
	root      string
	st        *store.Store
	fsw       *fsnotify.Watcher
	count     int
	dropped   bool
}

// New creates a Watcher rooted at root (typically the session's working
// directory) and adds watches for root and every non-excluded
// subdirectory, unless the tree is too large for the available file
// descriptors (see the package doc), in which case it watches only root.
// A failure here is non-fatal to the caller by design — File Plane
// visibility is best-effort, not a session precondition.
func New(sessionID, root string, st *store.Store) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}
	w := &Watcher{sessionID: sessionID, root: root, st: st, fsw: fsw}

	limit := raiseFDLimit()
	effectiveCap := MaxWatchedDirs
	if limit > 0 && int(limit)-fdHeadroom < effectiveCap {
		effectiveCap = int(limit) - fdHeadroom
	}
	if effectiveCap < 1 {
		effectiveCap = 1
	}

	dirs, err := eligibleDirs(root, effectiveCap+1)
	if err != nil {
		fsw.Close()
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}

	if len(dirs) > effectiveCap {
		if err := fsw.Add(root); err != nil {
			fsw.Close()
			return nil, fmt.Errorf("watch %s: %w", root, err)
		}
		fmt.Fprintf(os.Stderr,
			"leash: warning: %s has more than %d directories to watch (fd budget); File Plane degraded to root-only, not fully recursive\n",
			root, effectiveCap)
		return w, nil
	}

	var failed int
	for _, dir := range dirs {
		if err := fsw.Add(dir); err != nil {
			failed++
		}
	}
	if failed > 0 {
		// Per the fail-safe philosophy (ARCHITECTURE.md 0.7/0.9): a
		// best-effort sensor can have gaps, but it must not have them
		// silently. `_ = fsw.Add(path)` used to swallow this entirely.
		fmt.Fprintf(os.Stderr,
			"leash: warning: %d of %d directories under %s could not be watched; File Plane coverage is incomplete\n",
			failed, len(dirs), root)
	}

	return w, nil
}

// eligibleDirs walks root and returns every directory that would be
// watched (root itself plus non-excluded subdirectories), stopping early
// once it's collected more than limit — the caller only needs to know
// "does this fit the budget", not the full list, once it doesn't.
func eligibleDirs(root string, limit int) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole walk
		}
		if !d.IsDir() {
			return nil
		}
		// Compare by path, not by name, to decide whether this is the
		// walk's own root: comparing names (e.g. against ".") only works
		// when root is literally ".", but main.go always passes an
		// absolute cwd — a repo whose top-level directory happened to be
		// named e.g. "build" would otherwise exclude itself entirely.
		if path != root && excludedDirNames[d.Name()] {
			return filepath.SkipDir
		}
		dirs = append(dirs, path)
		if len(dirs) > limit {
			return filepath.SkipAll
		}
		return nil
	})
	return dirs, err
}

// getCurrentFDLimit reports the process's current open-file soft limit (0
// if it can't be read). Exported indirectly via CurrentFDLimit for
// `leash doctor`.
func getCurrentFDLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return rl.Cur
}

// CurrentFDLimit is the exported form of getCurrentFDLimit, for
// `leash doctor` to report the fd budget outside of a session.
func CurrentFDLimit() uint64 { return getCurrentFDLimit() }

// RaiseFDLimit is the exported form of raiseFDLimit, for `leash doctor` to
// report what fd budget a session would actually get without needing to
// construct a full Watcher.
func RaiseFDLimit() uint64 { return raiseFDLimit() }

// raiseFDLimit attempts to raise the process's open-file soft limit and
// returns the resulting limit (0 if it couldn't even be read). macOS in
// particular often defaults the soft limit to 256, which a mid-sized
// repo's directory count can exceed on its own — see the package doc for
// why running out matters beyond just File Plane.
func raiseFDLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	target := rl.Max
	if target > hardFDCap {
		target = hardFDCap
	}
	if target <= rl.Cur {
		return rl.Cur
	}
	rl.Cur = target
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		// The reported Max wasn't actually settable; don't just give up —
		// re-read whatever the limit ended up being (some platforms allow
		// a partial raise even when the requested value is rejected).
		var cur syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &cur); err == nil {
			return cur.Cur
		}
		return rl.Cur
	}
	return rl.Cur
}

func (w *Watcher) Close() error { return w.fsw.Close() }

// Run processes events until ctx is cancelled. Intended to be run in its
// own goroutine for the session's lifetime.
func (w *Watcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.handle(ev)
		case _, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			// Best-effort: a watcher error doesn't end the session, just
			// this stream of visibility.
		}
	}
}

func (w *Watcher) handle(ev fsnotify.Event) {
	base := filepath.Base(ev.Name)
	if excludedDirNames[base] {
		return
	}

	if ev.Has(fsnotify.Create) {
		// Lstat, not Stat: a newly created symlink must not be followed
		// into a watch. `git checkout` of a repo containing a symlink
		// (e.g. one pointing at /etc or $HOME) is a completely ordinary
		// event — following it here would start watching, and recording
		// mutations under, a path outside the session root entirely
		// (found in the v0.3 security review).
		if info, err := os.Lstat(ev.Name); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			_ = w.fsw.Add(ev.Name) // watch newly created directories too; best-effort like the initial walk
		}
	}

	op := operationName(ev.Op)
	if op == "" {
		return
	}

	rel, err := filepath.Rel(w.root, ev.Name)
	if err != nil {
		return
	}
	if !filepath.IsLocal(rel) {
		// The event path resolved outside the session root (e.g. via a
		// symlinked directory that slipped past the check above through
		// some other route). Don't record it — a single
		// strings.TrimPrefix(rel, "../") used to "clean" this, but only
		// strips one level, so "../../x" came out as "../x": still
		// escaped, just less obviously. Refusing to record is simpler
		// and actually correct.
		return
	}

	if w.count >= MaxEventsPerSession {
		if !w.dropped {
			w.dropped = true
			fmt.Fprintf(os.Stderr, "leash: file_mutation events capped at %d for this session; further file events are not recorded\n", MaxEventsPerSession)
		}
		return
	}
	w.count++

	if err := w.st.InsertEvent(w.sessionID, "file_mutation", "info", store.Allow, map[string]any{
		"path":      rel,
		"operation": op,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record file_mutation event: %v\n", err)
	}
}

func operationName(op fsnotify.Op) string {
	switch {
	case op.Has(fsnotify.Create):
		return "create"
	case op.Has(fsnotify.Write):
		return "write"
	case op.Has(fsnotify.Remove):
		return "remove"
	case op.Has(fsnotify.Rename):
		return "rename"
	case op.Has(fsnotify.Chmod):
		return "" // permission changes alone aren't interesting content mutations
	default:
		return ""
	}
}
