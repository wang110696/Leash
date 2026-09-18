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

	"github.com/wang110696/Leash/internal"
	"github.com/wang110696/Leash/internal/gitremote"
	"github.com/wang110696/Leash/internal/store"
)

// RunPrePushHook implements the pre-push hook contract: args are
// [remote-name, remote-url], and stdin carries one "<local-ref> <local-sha>
// <remote-ref> <remote-sha>" line per ref being pushed. Returns the process
// exit code — non-zero blocks the push.
func RunPrePushHook(args []string, stdin io.Reader) int {
	// Git requires the hook to consume stdin even when it isn't otherwise
	// needed, or the push can hang/fail confusingly.
	refCount := drainRefLines(stdin)

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "leash: pre-push hook invoked without remote name/URL; failing closed")
		return 1
	}
	remoteURL := args[1]

	sessionID := os.Getenv("LEASH_SESSION_ID")
	sessionDir := os.Getenv("LEASH_SESSION_DIR")
	dbPath := os.Getenv("LEASH_DB_PATH")

	st, err := store.Open(dbPath)
	if err != nil {
		st = nil // audit-only failure, doesn't change the decision below
	} else {
		defer st.Close()
	}

	normalized, err := gitremote.Normalize(remoteURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: pre-push hook BLOCK: could not normalize remote URL %q: %v\n", remoteURL, err)
		recordHookBlock(st, sessionID, "", err.Error(), refCount)
		return 1
	}

	known, err := internal.LoadKnownRemotes(sessionDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: pre-push hook BLOCK: %v\n", err)
		recordHookBlock(st, sessionID, normalized, "known-remotes snapshot unavailable", refCount)
		return 1
	}
	if !contains(known, normalized) {
		fmt.Fprintf(os.Stderr, "leash: pre-push hook BLOCK: %s not in this session's known-remote snapshot %v\n", normalized, known)
		recordHookBlock(st, sessionID, normalized, "destination not in session baseline", refCount)
		return 1
	}

	// Allowed: no event recorded here — the shim already recorded an
	// "allow" for this push when it ran (this hook only fires as a
	// backstop; if it fires *and* allows, the shim's own event is the
	// canonical audit record to avoid double-counting).
	return 0
}

func drainRefLines(stdin io.Reader) int {
	n := 0
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		n++
	}
	return n
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
