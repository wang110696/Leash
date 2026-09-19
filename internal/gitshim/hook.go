// Defense-in-depth pre-push hook (ARCHITECTURE.md 4.5/5.5): the shim is
// the primary interception point, but an agent that calls the real git
// binary by absolute path bypasses PATH-based shim resolution entirely.
// This hook is installed via session-scoped GIT_CONFIG_* environment
// overrides (see cmd/leash/main.go), not by writing to the user's real
// ~/.gitconfig, so it disappears with the session like everything else in
// v0.1/v0.2's "session-scoped, nothing permanent" design (ARCHITECTURE.md
// 0.6, 0.9).
//
// Unlike the shim, this hook doesn't need to resolve the push destination
// itself: git has already resolved it by the time it invokes the hook,
// and hands it the remote name and URL directly (see githooks(5),
// "pre-push").
package gitshim

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/wang110696/Leash/internal"
	"github.com/wang110696/Leash/internal/gitremote"
	"github.com/wang110696/Leash/internal/store"
)

// refUpdate is one line of pre-push hook stdin: <local-ref> <local-sha>
// <remote-ref> <remote-sha> (githooks(5), "pre-push").
type refUpdate struct {
	localRef, localSHA, remoteRef, remoteSHA string
}

// zeroSHA is what git uses in place of a ref that doesn't exist (a new
// branch being created, or a branch being deleted).
const zeroSHA = "0000000000000000000000000000000000000000"

// RunPrePushHook implements the pre-push hook contract: args are
// [remote-name, remote-url], and stdin carries one ref-update line per ref
// being pushed. Returns the process exit code — non-zero blocks the push.
func RunPrePushHook(args []string, stdin io.Reader) int {
	// Git requires the hook to consume stdin even when it isn't otherwise
	// needed, or the push can hang/fail confusingly.
	refs := readRefUpdates(stdin)

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "leash: pre-push hook invoked without remote name/URL; failing closed")
		return 1
	}
	remoteURL := args[1]

	sessionID := os.Getenv("LEASH_SESSION_ID")
	sessionDir := os.Getenv("LEASH_SESSION_DIR")
	dbPath := os.Getenv("LEASH_DB_PATH")
	realGit := os.Getenv("LEASH_REAL_GIT")

	st, err := store.Open(dbPath)
	if err != nil {
		st = nil // audit-only failure, doesn't change the decision below
	} else {
		defer st.Close()
	}

	normalized, err := gitremote.Normalize(remoteURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: pre-push hook BLOCK: could not normalize remote URL %q: %v\n", remoteURL, err)
		recordHookBlock(st, sessionID, "", err.Error(), len(refs))
		return 1
	}

	known, err := internal.LoadKnownRemotes(sessionDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: pre-push hook BLOCK: %v\n", err)
		recordHookBlock(st, sessionID, normalized, "known-remotes snapshot unavailable", len(refs))
		return 1
	}
	if !contains(known, normalized) {
		fmt.Fprintf(os.Stderr, "leash: pre-push hook BLOCK: %s not in this session's known-remote snapshot %v\n", normalized, known)
		recordHookBlock(st, sessionID, normalized, "destination not in session baseline", len(refs))
		return 1
	}

	// Allowed. The shim already recorded the "allow" decision for this
	// push (this hook only fires as a shim-bypass backstop, see package
	// doc) — but the hook is the only place that has the exact
	// local/remote SHA pair per ref, so it's the right place to capture a
	// `--stat` summary of what's actually being pushed (Flight Recorder /
	// dashboard "diff viewer", ARCHITECTURE.md 10.1 v0.3). Recorded as a
	// distinct kind, not "git_push", so it doesn't double the allow/block
	// tally in store.Summary.
	for _, r := range refs {
		recordDiffStat(st, sessionID, realGit, normalized, r)
	}
	return 0
}

func readRefUpdates(stdin io.Reader) []refUpdate {
	var refs []refUpdate
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 4 {
			continue
		}
		refs = append(refs, refUpdate{localRef: fields[0], localSHA: fields[1], remoteRef: fields[2], remoteSHA: fields[3]})
	}
	return refs
}

func recordDiffStat(st *store.Store, sessionID, realGit, normalizedRemote string, r refUpdate) {
	if st == nil || realGit == "" {
		return
	}
	if r.localSHA == zeroSHA {
		return // a branch/tag deletion: nothing was pushed to diff
	}

	var statRange string
	if r.remoteSHA == zeroSHA {
		// New branch: there's no prior remote state to diff against.
		// Summarize what's being introduced instead of a range diff.
		statRange = r.localSHA
	} else {
		statRange = r.remoteSHA + ".." + r.localSHA
	}

	out, err := exec.Command(realGit, "diff", "--stat", statRange).Output()
	stat := strings.TrimSpace(string(out))
	if err != nil || stat == "" {
		return // best-effort enrichment; a failure here doesn't affect the push decision
	}
	// --stat output is file paths + line-count magnitudes only, never
	// code content — safe to store under the same "no raw secrets"
	// discipline as every other event (ARCHITECTURE.md 0.8/0.9). Still
	// capped defensively in case of an unexpectedly huge changeset.
	const maxStatLen = 4000
	if len(stat) > maxStatLen {
		stat = stat[:maxStatLen] + "\n... (truncated)"
	}

	if err := st.InsertEvent(sessionID, "git_diff_stat", "info", store.Allow, map[string]any{
		"remote":     normalizedRemote,
		"local_ref":  r.localRef,
		"local_sha":  r.localSHA,
		"remote_sha": r.remoteSHA,
		"stat":       stat,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record git_diff_stat event: %v\n", err)
	}
}

func recordHookBlock(st *store.Store, sessionID, normalizedRemote, reason string, refCount int) {
	if st == nil {
		return
	}
	if err := st.InsertEvent(sessionID, "git_push", "high", store.Block, map[string]any{
		"remote": normalizedRemote,
		"reason": reason,
		"source": "pre-push-hook", // distinguishes shim-bypass catches from normal shim blocks
		"refs":   refCount,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record git_push (hook) event: %v\n", err)
	}
}
