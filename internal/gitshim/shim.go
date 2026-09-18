// Package gitshim implements the v0.1 Git Sensor. It is invoked as a
// process literally named "git" (see cmd/leash/main.go — a self-symlink
// trick, not a separate binary), placed on PATH only for the duration of
// one `leash run` session (ARCHITECTURE.md section 0.6).
//
// Scope, per ARCHITECTURE.md 0.6/0.7: only `git push` is security-sensitive
// and fails closed. Every other subcommand passes straight through to the
// real git binary, unaudited — v0.1 does not scan commit content.
package gitshim

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/wang110696/Leash/internal"
	"github.com/wang110696/Leash/internal/gitremote"
	"github.com/wang110696/Leash/internal/store"
)

// Run executes the shim and returns the process exit code.
func Run(args []string) int {
	realGit := os.Getenv("LEASH_REAL_GIT")
	if realGit == "" {
		fmt.Fprintln(os.Stderr, "leash: LEASH_REAL_GIT is not set; this git shim should only be invoked inside `leash run` — refusing to guess a real git path")
		return 1
	}

	isPush, pushArgs, configArgs := resolveInvocation(realGit, args)
	if !isPush {
		return passthrough(realGit, args)
	}

	return handlePush(realGit, args, pushArgs, configArgs)
}

func passthrough(realGit string, args []string) int {
	cmd := exec.Command(realGit, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "leash: failed to exec real git: %v\n", err)
		return 1
	}
	return 0
}

// handlePush gates the push. originalArgs is exactly what the user/agent
// typed (including any global options or alias name) — that's what's
// replayed to real git on allow, so real git re-resolves aliases/config
// itself rather than us reconstructing an equivalent invocation. pushArgs
// and configArgs come from resolveInvocation's walk (see parse.go).
func handlePush(realGit string, originalArgs, pushArgs, configArgs []string) int {
	sessionID := os.Getenv("LEASH_SESSION_ID")
	sessionDir := os.Getenv("LEASH_SESSION_DIR")
	dbPath := os.Getenv("LEASH_DB_PATH")

	st, err := store.Open(dbPath)
	if err != nil {
		// Can't even log the decision reliably. The push itself is still
		// gated on the remote check below; a store failure alone doesn't
		// change the allow/block outcome, it only means we can't audit it.
		fmt.Fprintf(os.Stderr, "leash: warning: could not open event store: %v\n", err)
		st = nil
	} else {
		defer st.Close()
	}

	dests, err := resolveDestination(realGit, pushArgs, configArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: BLOCK git push: %v\n", err)
		recordPush(st, sessionID, store.Block, "", err.Error())
		return 1
	}

	// A remote can have multiple pushurls (`git remote set-url --push
	// --add`) — real git pushes to *all* of them, so every one must be in
	// the baseline, not just the first (V3). Blocking the whole push if
	// any single pushurl is unapproved is the fail-closed choice.
	var normalized []string
	for _, d := range dests {
		n, err := gitremote.Normalize(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "leash: BLOCK git push: could not normalize destination %q: %v\n", d, err)
			recordPush(st, sessionID, store.Block, strings.Join(normalized, ","), err.Error())
			return 1
		}
		normalized = append(normalized, n)
	}

	known, err := internal.LoadKnownRemotes(sessionDir)
	if err != nil {
		// Fail closed: can't confirm the baseline, so we can't confirm the
		// push is safe (ARCHITECTURE.md 0.7).
		fmt.Fprintf(os.Stderr, "leash: BLOCK git push: %v\n", err)
		recordPush(st, sessionID, store.Block, strings.Join(normalized, ","), "known-remotes snapshot unavailable")
		return 1
	}

	for _, n := range normalized {
		if !contains(known, n) {
			fmt.Fprintf(os.Stderr, "leash: BLOCK git push to %s: not in this session's known-remote snapshot %v\n", n, known)
			recordPush(st, sessionID, store.Block, strings.Join(normalized, ","), "destination not in session baseline")
			return 1
		}
	}

	recordPush(st, sessionID, store.Allow, strings.Join(normalized, ","), "")
	return passthrough(realGit, originalArgs)
}

// remoteNameRe matches typical git remote *names* (e.g. "origin",
// "upstream"), as opposed to a URL or scp-like destination given directly
// to `git push`.
var remoteNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// resolveDestination extracts the explicit push destination(s) from `git
// push`'s arguments (pushArgs is everything after the "push" token itself
// — see resolveInvocation). Per ARCHITECTURE.md 0.6, only `git push
// <remote>` and `git push <url>` are supported — bare `git push` (relying
// on implicit upstream/pushDefault resolution) is treated as unresolved
// and blocked rather than reimplementing git's destination-resolution
// semantics.
//
// Returns multiple destinations when the token names a remote configured
// with more than one pushurl (V3) — real git pushes to all of them.
// configArgs (captured `-c` flags from the original invocation) are
// replayed here so remote resolution sees the same config the real push
// will (V2).
func resolveDestination(realGit string, pushArgs, configArgs []string) ([]string, error) {
	var token string
	for i := 0; i < len(pushArgs); i++ {
		a := pushArgs[i]
		if a == "--" {
			if i+1 < len(pushArgs) {
				token = pushArgs[i+1]
			}
			break
		}
		if strings.HasPrefix(a, "-") {
			if pushOptsWithValue[a] {
				i++ // skip its value token too — otherwise e.g. `-o origin
				// <evil-url>` misreads "origin" as the destination
				// (V4).
			}
			continue
		}
		token = a
		break
	}
	if token == "" {
		return nil, fmt.Errorf("bare `git push` (implicit destination) is not supported by the v0.1 shim; use `git push <remote>` or `git push <url>`")
	}

	if !remoteNameRe.MatchString(token) {
		// Looks like a URL or scp-like destination already.
		return []string{token}, nil
	}

	urls, err := remotePushURLs(realGit, configArgs, token)
	if err != nil {
		return nil, fmt.Errorf("could not resolve remote %q via `git remote get-url`: %w", token, err)
	}
	return urls, nil
}

// remotePushURLs returns every pushurl configured for a remote (falling
// back to its fetch url(s) if no pushurl is set, matching git's own
// fallback), using `--all` so a remote with multiple pushurls
// (`git remote set-url --push --add`) doesn't have all but the first
// silently ignored (V3).
func remotePushURLs(realGit string, configArgs []string, remoteName string) ([]string, error) {
	getURL := func(extraArgs ...string) ([]string, error) {
		cmdArgs := append(append([]string{}, configArgs...), "remote", "get-url", "--all")
		cmdArgs = append(cmdArgs, extraArgs...)
		cmdArgs = append(cmdArgs, remoteName)
		out, err := exec.Command(realGit, cmdArgs...).Output()
		if err != nil {
			return nil, err
		}
		var urls []string
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				urls = append(urls, line)
			}
		}
		if len(urls) == 0 {
			return nil, fmt.Errorf("remote %q resolved to no URLs", remoteName)
		}
		return urls, nil
	}

	if urls, err := getURL("--push"); err == nil {
		return urls, nil
	}
	return getURL()
}

func recordPush(st *store.Store, sessionID string, decision store.Decision, normalizedRemote, reason string) {
	if st == nil {
		return
	}
	severity := "info"
	if decision == store.Block {
		severity = "high"
	}
	if err := st.InsertEvent(sessionID, "git_push", severity, decision, map[string]any{
		"remote": normalizedRemote,
		"reason": reason,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record git_push event: %v\n", err)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
