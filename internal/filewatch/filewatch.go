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
// new watches for directories created during the session. Two safety
// valves keep this from becoming a liability during an active coding
// session (compilers, package managers, and editors can generate a lot of
// churn):
//   - a fixed exclude-list of common noisy directories (.git, node_modules,
//     vendor, build output, ...) skipped entirely, not even watched
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
	"strings"

	"github.com/fsnotify/fsnotify"

	"github.com/wang110696/Leash/internal/store"
)

// MaxEventsPerSession caps how many file_mutation events a single session
// will record, independent of how long it runs or how much churn happens.
// A var (not a const) so tests can lower it to exercise the cap without
// generating 5000 real filesystem events.
var MaxEventsPerSession = 5000

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
// subdirectory. A failure here is non-fatal to the caller by design — File
// Plane visibility is best-effort, not a session precondition.
func New(sessionID, root string, st *store.Store) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	w := &Watcher{sessionID: sessionID, root: root, st: st, fsw: fsw}

	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole walk
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() != "." && excludedDirNames[d.Name()] {
			return filepath.SkipDir
		}
		_ = fsw.Add(path) // best-effort per-directory; one bad dir shouldn't stop the rest
		return nil
	}); err != nil {
		fsw.Close()
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}

	return w, nil
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
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			_ = w.fsw.Add(ev.Name) // watch newly created directories too
		}
	}

	op := operationName(ev.Op)
	if op == "" {
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

	rel, err := filepath.Rel(w.root, ev.Name)
	if err != nil {
		rel = ev.Name
	}
	// Defensive: never let a path escape the session root into the stored
	// event (e.g. via a symlink) as an absolute path — relative-only,
	// matching the "don't leak more than necessary" posture applied to
	// network paths (E5) and process argv.
	rel = strings.TrimPrefix(rel, "../")

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
