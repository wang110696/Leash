// Command leash is both the CLI entry point and, via a self-symlink
// trick, the git shim binary: cmd/leash/main.go checks its own argv[0]
// and dispatches to internal/gitshim when invoked as "git" (see runSession
// below, which creates the symlink). This keeps v0.1 to one built binary,
// per ARCHITECTURE.md section 0.4 — no separate leash-git-shim binary.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wang110696/Leash/internal"
	"github.com/wang110696/Leash/internal/ca"
	"github.com/wang110696/Leash/internal/gitremote"
	"github.com/wang110696/Leash/internal/gitshim"
	"github.com/wang110696/Leash/internal/proxy"
	"github.com/wang110696/Leash/internal/store"
)

func main() {
	if filepath.Base(os.Args[0]) == "git" {
		os.Exit(gitshim.Run(os.Args[1:]))
	}

	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: leash run -- <command> [args...]")
		os.Exit(2)
	}

	command := os.Args[2:]
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "usage: leash run -- <command> [args...]")
		os.Exit(2)
	}

	code, err := runSession(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runSession(command []string) (int, error) {
	sessionID, err := internal.NewSessionID()
	if err != nil {
		return 0, fmt.Errorf("generate session id: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return 0, fmt.Errorf("get working directory: %w", err)
	}

	// Resolve the real git binary BEFORE anything modifies PATH for a child
	// process, to avoid the shim finding itself (ARCHITECTURE.md 0.6).
	realGit, err := exec.LookPath("git")
	if err != nil {
		return 0, fmt.Errorf("resolve real git binary: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return 0, fmt.Errorf("resolve home directory: %w", err)
	}
	leashDir := filepath.Join(home, ".leash")

	certPEM, keyPEM, caPaths, err := ca.Ensure(leashDir)
	if err != nil {
		return 0, fmt.Errorf("ensure local CA: %w", err)
	}

	dbPath := filepath.Join(leashDir, "events.db")
	st, err := store.Open(dbPath)
	if err != nil {
		return 0, fmt.Errorf("open event store: %w", err)
	}
	defer st.Close()

	px, err := proxy.New(sessionID, st, certPEM, keyPEM)
	if err != nil {
		return 0, fmt.Errorf("start proxy: %w", err)
	}
	defer px.Close()

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- px.Serve() }()

	sessionDir := filepath.Join(leashDir, "sessions", sessionID)
	shimBinDir := filepath.Join(sessionDir, "bin")
	if err := os.MkdirAll(shimBinDir, 0o700); err != nil {
		return 0, fmt.Errorf("create session shim dir: %w", err)
	}
	defer os.RemoveAll(sessionDir) // the shim symlink isn't needed once the session ends

	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve leash's own executable path: %w", err)
	}
	shimPath := filepath.Join(shimBinDir, "git")
	if err := os.Symlink(self, shimPath); err != nil {
		return 0, fmt.Errorf("install session-scoped git shim: %w", err)
	}

	remotes := snapshotKnownRemotes(realGit, cwd)
	if err := internal.SaveKnownRemotes(sessionDir, remotes); err != nil {
		return 0, fmt.Errorf("save known-remotes snapshot: %w", err)
	}

	fmt.Fprintf(os.Stderr, "leash: session %s started, proxy on %s, known remotes: %v\n",
		sessionID, px.Addr(), remotes)

	childEnv := buildChildEnv(sessionID, sessionDir, dbPath, realGit, px.Addr(), caPaths.CertPath, shimBinDir)

	// exec.Command resolves a bare command name via the *calling* process's
	// PATH, not cmd.Env's — so if we passed command[0] straight through,
	// `leash run -- git ...` would silently bypass the shim (it would
	// still work when the launched agent itself later spawns "git", since
	// that lookup happens inside the agent's own process using its
	// inherited env). Resolve explicitly against childEnv's PATH instead.
	resolvedPath, err := lookPathIn(command[0], childEnv)
	if err != nil {
		return 0, fmt.Errorf("resolve %q: %w", command[0], err)
	}

	cmd := exec.Command(resolvedPath, command[1:]...)
	cmd.Env = childEnv
	cmd.Dir = cwd
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()

	summary, sumErr := st.Summary(sessionID)
	if sumErr == nil {
		fmt.Fprintf(os.Stderr, "leash: session %s ended — allow=%d warn=%d block=%d\n",
			sessionID, summary.Allow, summary.Warn, summary.Block)
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 0, fmt.Errorf("run %s: %w", command[0], runErr)
	}
	return 0, nil
}

// lookPathIn resolves file to an executable path using PATH from env
// (mirroring exec.LookPath, which only ever consults the calling process's
// own environment — not the env we're about to hand to a child).
func lookPathIn(file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return file, nil
	}
	var pathVal string
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			pathVal = kv[len("PATH="):]
			break
		}
	}
	for _, dir := range strings.Split(pathVal, string(os.PathListSeparator)) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, file)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			// Return an absolute path: a relative candidate (e.g. from an
			// empty PATH segment resolving to ".") would otherwise be
			// re-resolved against the *parent* process's PATH by
			// exec.Command, reopening the exact bug this function exists
			// to close.
			return filepath.Abs(candidate)
		}
	}
	return "", fmt.Errorf("%s: executable file not found in $PATH", file)
}

// snapshotKnownRemotes captures the normalized identity of every remote
// configured in the repo at repoDir, at session start. A push destination
// outside this baseline is blocked (ARCHITECTURE.md 5.5). If repoDir isn't
// a git repo, the baseline is simply empty — which means any later `git
// push` will fail closed, which is the correct default.
//
// Uses `--all` so a remote configured with more than one pushurl
// (`git remote set-url --push --add`) has every one snapshotted, matching
// the `--all` used when actually resolving a push destination (V3 in the
// v0.1 security review — the two sides must agree on what "known" means).
func snapshotKnownRemotes(realGit, repoDir string) []string {
	out, err := exec.Command(realGit, "-C", repoDir, "remote").Output()
	if err != nil {
		return nil
	}

	var remotes []string
	for _, name := range strings.Fields(string(out)) {
		urlOut, err := exec.Command(realGit, "-C", repoDir, "remote", "get-url", "--push", "--all", name).Output()
		if err != nil {
			urlOut, err = exec.Command(realGit, "-C", repoDir, "remote", "get-url", "--all", name).Output()
			if err != nil {
				continue
			}
		}
		for _, line := range strings.Split(strings.TrimSpace(string(urlOut)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			norm, err := gitremote.Normalize(line)
			if err != nil {
				continue
			}
			remotes = append(remotes, norm)
		}
	}
	return remotes
}

// buildChildEnv constructs the environment injected into the launched
// agent process tree: proxy + CA env vars, and the session-scoped git shim
// prepended to PATH. Per ARCHITECTURE.md 0.5, CA trust is scoped to what
// Codex CLI and curl need — not a general N-harness compatibility matrix.
func buildChildEnv(sessionID, sessionDir, dbPath, realGit, proxyAddr, caCertPath, shimBinDir string) []string {
	env := os.Environ()

	set := func(env []string, key, val string) []string {
		prefix := key + "="
		for i, kv := range env {
			if strings.HasPrefix(kv, prefix) {
				env[i] = prefix + val
				return env
			}
		}
		return append(env, prefix+val)
	}

	del := func(env []string, key string) []string {
		prefix := key + "="
		out := env[:0]
		for _, kv := range env {
			if !strings.HasPrefix(kv, prefix) {
				out = append(out, kv)
			}
		}
		return out
	}

	proxyURL := "http://" + proxyAddr
	env = set(env, "HTTP_PROXY", proxyURL)
	env = set(env, "HTTPS_PROXY", proxyURL)
	env = set(env, "http_proxy", proxyURL)
	env = set(env, "https_proxy", proxyURL)

	// An inherited NO_PROXY (common in corporate shells, e.g.
	// "NO_PROXY=internal.corp,github.com") would let the child connect
	// directly to those hosts, bypassing the Egress Sensor entirely — a
	// real bypass in the v0.1 security review (V6). ALL_PROXY could
	// likewise redirect traffic to a different (unaudited) proxy. Both are
	// cleared rather than merely overridden with a placeholder, since an
	// empty value is what curl/git/Node/etc. treat as "no exceptions".
	env = set(env, "NO_PROXY", "")
	env = set(env, "no_proxy", "")
	env = del(env, "ALL_PROXY")
	env = del(env, "all_proxy")

	env = set(env, "LEASH_SESSION_ID", sessionID)
	env = set(env, "LEASH_SESSION_DIR", sessionDir)
	env = set(env, "LEASH_DB_PATH", dbPath)
	env = set(env, "LEASH_REAL_GIT", realGit)

	// CA trust, env-only (ARCHITECTURE.md 0.5) — no system trust store change.
	// GIT_SSL_CAINFO is needed too: git's HTTPS transport does not honor
	// SSL_CERT_FILE, it has its own CA env var.
	env = set(env, "CODEX_CA_CERTIFICATE", caCertPath)
	env = set(env, "SSL_CERT_FILE", caCertPath)
	env = set(env, "CURL_CA_BUNDLE", caCertPath)
	env = set(env, "GIT_SSL_CAINFO", caCertPath)

	for i, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			env[i] = "PATH=" + shimBinDir + string(os.PathListSeparator) + kv[len("PATH="):]
			return env
		}
	}
	return append(env, "PATH="+shimBinDir)
}
