package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.Index(kv, "="); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// TestBuildChildEnv_ScrubsProxyBypass is a regression test for V6: an
// inherited NO_PROXY/ALL_PROXY from the parent shell must not survive into
// the launched agent's environment, or it would let traffic route around
// the Egress Sensor entirely.
func TestBuildChildEnv_ScrubsProxyBypass(t *testing.T) {
	orig := os.Environ()
	defer func() {
		os.Clearenv()
		for _, kv := range orig {
			if i := strings.Index(kv, "="); i >= 0 {
				os.Setenv(kv[:i], kv[i+1:])
			}
		}
	}()

	os.Setenv("NO_PROXY", "internal.corp,github.com")
	os.Setenv("no_proxy", "internal.corp,github.com")
	os.Setenv("ALL_PROXY", "socks5://127.0.0.1:1080")
	os.Setenv("all_proxy", "socks5://127.0.0.1:1080")
	os.Setenv("PATH", "/usr/bin:/bin")

	env := buildChildEnv("sess1", "/tmp/sessdir", "/tmp/events.db", "/usr/bin/git",
		"127.0.0.1:12345", "/tmp/ca.pem", "/tmp/shimbin", "/tmp/sessdir/git-hooks")
	m := envMap(env)

	if v, ok := m["NO_PROXY"]; !ok || v != "" {
		t.Errorf("NO_PROXY = %q, present=%v; want empty (V6 regression)", v, ok)
	}
	if v, ok := m["no_proxy"]; !ok || v != "" {
		t.Errorf("no_proxy = %q, present=%v; want empty (V6 regression)", v, ok)
	}
	if _, ok := m["ALL_PROXY"]; ok {
		t.Errorf("ALL_PROXY still present in child env; want it removed (V6 regression)")
	}
	if _, ok := m["all_proxy"]; ok {
		t.Errorf("all_proxy still present in child env; want it removed (V6 regression)")
	}

	if got := m["HTTPS_PROXY"]; got != "http://127.0.0.1:12345" {
		t.Errorf("HTTPS_PROXY = %q; want the leash proxy address", got)
	}

	if !strings.HasPrefix(m["PATH"], "/tmp/shimbin") {
		t.Errorf("PATH = %q; want shim dir prepended", m["PATH"])
	}

	if got := m["NODE_EXTRA_CA_CERTS"]; got != "/tmp/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q; want the CA path (Claude Code harness support)", got)
	}
}

func TestAppendGitConfigOverride(t *testing.T) {
	t.Run("no prior GIT_CONFIG_COUNT", func(t *testing.T) {
		env := appendGitConfigOverride([]string{"PATH=/bin"}, "core.hooksPath", "/tmp/hooks")
		m := envMap(env)
		if m["GIT_CONFIG_COUNT"] != "1" {
			t.Fatalf("GIT_CONFIG_COUNT = %q; want 1", m["GIT_CONFIG_COUNT"])
		}
		if m["GIT_CONFIG_KEY_0"] != "core.hooksPath" || m["GIT_CONFIG_VALUE_0"] != "/tmp/hooks" {
			t.Fatalf("GIT_CONFIG_KEY_0/VALUE_0 = %q/%q; want core.hooksPath//tmp/hooks", m["GIT_CONFIG_KEY_0"], m["GIT_CONFIG_VALUE_0"])
		}
	})

	t.Run("appends after an existing override instead of clobbering it", func(t *testing.T) {
		env := []string{
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=user.name",
			"GIT_CONFIG_VALUE_0=someone",
		}
		env = appendGitConfigOverride(env, "core.hooksPath", "/tmp/hooks")
		m := envMap(env)
		if m["GIT_CONFIG_COUNT"] != "2" {
			t.Fatalf("GIT_CONFIG_COUNT = %q; want 2", m["GIT_CONFIG_COUNT"])
		}
		if m["GIT_CONFIG_KEY_0"] != "user.name" || m["GIT_CONFIG_VALUE_0"] != "someone" {
			t.Fatalf("existing override at index 0 was clobbered: %q=%q", m["GIT_CONFIG_KEY_0"], m["GIT_CONFIG_VALUE_0"])
		}
		if m["GIT_CONFIG_KEY_1"] != "core.hooksPath" || m["GIT_CONFIG_VALUE_1"] != "/tmp/hooks" {
			t.Fatalf("new override not appended at index 1: %q=%q", m["GIT_CONFIG_KEY_1"], m["GIT_CONFIG_VALUE_1"])
		}
	})
}

// TestLookPathIn_ReturnsAbsolutePath is a regression test for E6: a
// relative candidate (e.g. from an empty PATH segment resolving to ".")
// must come back absolute, otherwise exec.Command would re-resolve it
// against the *parent* process's PATH — reopening the bug lookPathIn
// exists to close.
func TestLookPathIn_ReturnsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "mytool")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := lookPathIn("mytool", []string{"PATH=" + dir})
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("lookPathIn returned %q; want an absolute path", got)
	}
	if got != binPath {
		t.Fatalf("lookPathIn = %q; want %q", got, binPath)
	}
}

func TestLookPathIn_NotFound(t *testing.T) {
	if _, err := lookPathIn("definitely-not-a-real-command-xyz", []string{"PATH=/usr/bin"}); err == nil {
		t.Fatal("lookPathIn found a nonexistent command; want an error")
	}
}

func TestLookPathIn_PathWithSlashPassesThrough(t *testing.T) {
	got, err := lookPathIn("/bin/sh", []string{"PATH=/nonexistent"})
	if err != nil {
		t.Fatalf("lookPathIn: %v", err)
	}
	if got != "/bin/sh" {
		t.Fatalf("lookPathIn(%q) = %q; want unchanged", "/bin/sh", got)
	}
}
