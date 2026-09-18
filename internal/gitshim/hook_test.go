package gitshim

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wang110696/Leash/internal"
)

// RunPrePushHook makes its decision purely from args + stdin + env (it
// never talks to the network or invokes real git itself — git has already
// resolved the destination and handles the actual push separately), so it
// can be tested directly without a real repo or network access.
func setupHookEnv(t *testing.T, knownRemotes []string) {
	t.Helper()
	sessionDir := t.TempDir()
	if err := internal.SaveKnownRemotes(sessionDir, knownRemotes); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEASH_SESSION_ID", "test-session")
	t.Setenv("LEASH_SESSION_DIR", sessionDir)
	t.Setenv("LEASH_DB_PATH", filepath.Join(sessionDir, "events.db"))
}

func TestRunPrePushHook_BlocksUnknownRemote(t *testing.T) {
	setupHookEnv(t, []string{"github.com/known/repo"})

	stdin := strings.NewReader("refs/heads/main abc123 refs/heads/main def456\n")
	code := RunPrePushHook([]string{"origin", "https://github.com/attacker/evil.git"}, stdin)
	if code == 0 {
		t.Fatal("RunPrePushHook = 0 (allowed); want non-zero (blocked) for an unknown remote")
	}
}

func TestRunPrePushHook_AllowsKnownRemote(t *testing.T) {
	setupHookEnv(t, []string{"github.com/known/repo"})

	stdin := strings.NewReader("refs/heads/main abc123 refs/heads/main def456\n")
	code := RunPrePushHook([]string{"origin", "https://github.com/known/repo.git"}, stdin)
	if code != 0 {
		t.Fatalf("RunPrePushHook = %d; want 0 (allowed) for a remote in the known baseline", code)
	}
}

func TestRunPrePushHook_FailsClosedOnUnnormalizableURL(t *testing.T) {
	setupHookEnv(t, []string{"github.com/known/repo"})

	// A local filesystem path isn't a URL form gitremote.Normalize
	// recognizes — this must fail closed (block), not be silently allowed
	// through because normalization "didn't apply".
	stdin := strings.NewReader("refs/heads/main abc123 refs/heads/main def456\n")
	code := RunPrePushHook([]string{"origin", "/tmp/some/local/path.git"}, stdin)
	if code == 0 {
		t.Fatal("RunPrePushHook = 0 (allowed); want non-zero (blocked) when the destination can't be normalized")
	}
}

func TestRunPrePushHook_FailsClosedOnMissingBaseline(t *testing.T) {
	// No LEASH_SESSION_DIR set up at all (or pointing somewhere with no
	// known_remotes.json) — must fail closed, not treat "can't confirm" as
	// "assume safe".
	dir := t.TempDir() // empty dir, no known_remotes.json snapshot written
	t.Setenv("LEASH_SESSION_ID", "test-session")
	t.Setenv("LEASH_SESSION_DIR", dir)
	t.Setenv("LEASH_DB_PATH", filepath.Join(dir, "events.db"))

	stdin := strings.NewReader("refs/heads/main abc123 refs/heads/main def456\n")
	code := RunPrePushHook([]string{"origin", "https://github.com/known/repo.git"}, stdin)
	if code == 0 {
		t.Fatal("RunPrePushHook = 0 (allowed); want non-zero (blocked) when the baseline snapshot is missing")
	}
}

func TestRunPrePushHook_RequiresRemoteArgs(t *testing.T) {
	code := RunPrePushHook(nil, strings.NewReader(""))
	if code == 0 {
		t.Fatal("RunPrePushHook(nil args) = 0; want non-zero")
	}
	code = RunPrePushHook([]string{"origin"}, strings.NewReader(""))
	if code == 0 {
		t.Fatal("RunPrePushHook([origin]) = 0; want non-zero (missing URL arg)")
	}
}

func TestRunPrePushHook_DrainsStdinEvenOnEarlyBlock(t *testing.T) {
	// Git expects the hook to consume stdin regardless of outcome; make
	// sure a large ref list doesn't hang or panic.
	setupHookEnv(t, nil)
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		sb.WriteString("refs/heads/branch abc123 refs/heads/branch def456\n")
	}
	code := RunPrePushHook([]string{"origin", "https://github.com/unknown/repo.git"}, strings.NewReader(sb.String()))
	if code == 0 {
		t.Fatal("expected block for unknown remote even with many ref lines on stdin")
	}
}
