package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/wang110696/Leash/internal/dashboard"
	"github.com/wang110696/Leash/internal/store"
)

// runDashboard serves the local "Flight Recorder" web UI (ARCHITECTURE.md
// 10.1 v0.3) over the same events.db every `leash run` session writes to.
// Read-only, 127.0.0.1-only — this is a viewer for what's already been
// recorded, not a control surface.
func runDashboard(args []string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: %v\n", err)
		return 1
	}
	leashDir := filepath.Join(home, ".leash")
	if err := os.MkdirAll(leashDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "leash: %v\n", err)
		return 1
	}
	dbPath := filepath.Join(leashDir, "events.db")

	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: open event store: %v\n", err)
		return 1
	}
	defer st.Close()

	addr := "127.0.0.1:0"
	if len(args) > 0 && args[0] != "" {
		addr = args[0]
		if !strings.Contains(addr, ":") {
			addr = "127.0.0.1:" + addr // convenience: `leash dashboard 7777`
		}
	}

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leash: bind dashboard listener: %v\n", err)
		return 1
	}

	warnIfNotLoopback(ln.Addr().String())

	fmt.Fprintf(os.Stderr, "leash: dashboard on http://%s (Ctrl+C to stop)\n", ln.Addr())
	if err := http.Serve(ln, dashboard.New(st)); err != nil {
		fmt.Fprintf(os.Stderr, "leash: dashboard server: %v\n", err)
		return 1
	}
	return 0
}

// warnIfNotLoopback prints a prominent warning when the dashboard is bound
// somewhere reachable from outside this machine. It's unauthenticated and
// serves recorded audit data (hostnames, file paths, remote names, diff
// stats) — binding it to a LAN-reachable address should be a deliberate,
// visible choice, not something a user does by accident with one flag
// (found in the v0.3 security review).
func warnIfNotLoopback(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return
	}
	fmt.Fprintf(os.Stderr, "leash: WARNING: dashboard is bound to %s, not just this machine — anyone who can reach it on your network can read your audit data without logging in. Use a loopback address (127.0.0.1) unless you specifically mean to expose it.\n", addr)
}
