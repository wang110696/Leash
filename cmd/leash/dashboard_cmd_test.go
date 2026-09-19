package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestWarnIfNotLoopback_WarnsOnNonLocalAddr(t *testing.T) {
	cases := []string{"0.0.0.0:7777", "192.168.1.5:7777", "10.0.0.1:7777"}
	for _, addr := range cases {
		out := captureStderr(t, func() { warnIfNotLoopback(addr) })
		if !strings.Contains(out, "WARNING") {
			t.Errorf("warnIfNotLoopback(%q) printed nothing warning-like; got %q", addr, out)
		}
	}
}

func TestWarnIfNotLoopback_SilentOnLoopback(t *testing.T) {
	cases := []string{"127.0.0.1:7777", "localhost:7777", "127.0.0.1:0"}
	for _, addr := range cases {
		out := captureStderr(t, func() { warnIfNotLoopback(addr) })
		if out != "" {
			t.Errorf("warnIfNotLoopback(%q) printed %q; want silence for a loopback address", addr, out)
		}
	}
}
