package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestInsertAndSummary(t *testing.T) {
	st := openTestStore(t)

	events := []struct {
		kind     string
		decision Decision
	}{
		{"network", Allow},
		{"network", Allow},
		{"network", Block},
		{"git_push", Allow},
		{"git_push", Block},
	}
	for _, e := range events {
		if err := st.InsertEvent("sess-a", e.kind, "info", e.decision, map[string]any{"x": 1}); err != nil {
			t.Fatalf("InsertEvent: %v", err)
		}
	}
	// A different session's events must not leak into sess-a's summary.
	if err := st.InsertEvent("sess-b", "network", "info", Allow, map[string]any{}); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}

	sum, err := st.Summary("sess-a")
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.Allow != 3 || sum.Block != 2 || sum.Warn != 0 {
		t.Fatalf("Summary(sess-a) = %+v; want {Allow:3 Warn:0 Block:2}", sum)
	}

	sumB, err := st.Summary("sess-b")
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sumB.Allow != 1 {
		t.Fatalf("Summary(sess-b) = %+v; want Allow:1", sumB)
	}
}

// TestConcurrentWrites exercises the busy_timeout DSN parameter (E4): the
// proxy and every git-shim invocation open this same database file
// independently and can write concurrently in real usage. Without a busy
// timeout, modernc.org/sqlite fails an overlapping write immediately with
// "database is locked" instead of waiting.
func TestConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")

	const writers = 8
	const perWriter = 5
	errCh := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			st, err := Open(path) // each "writer" opens its own connection, like the real proxy/shim processes do
			if err != nil {
				errCh <- err
				return
			}
			defer st.Close()
			for j := 0; j < perWriter; j++ {
				if err := st.InsertEvent("sess", "network", "info", Allow, map[string]any{"i": i, "j": j}); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(i)
	}

	for i := 0; i < writers; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent writer failed (busy_timeout regression, E4): %v", err)
		}
	}

	st := openTestStore2(t, path)
	sum, err := st.Summary("sess")
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if sum.Allow != writers*perWriter {
		t.Fatalf("Summary.Allow = %d; want %d", sum.Allow, writers*perWriter)
	}
}

func TestPrune(t *testing.T) {
	st := openTestStore(t)

	now := time.Now()
	insertAt := func(sessionID string, ts time.Time) {
		t.Helper()
		if _, err := st.db.Exec(
			`INSERT INTO events (session_id, ts, kind, severity, decision, payload_json) VALUES (?, ?, 'network', 'info', 'allow', '{}')`,
			sessionID, ts.UnixMilli(),
		); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	insertAt("old", now.Add(-40*24*time.Hour))    // older than 30d retention
	insertAt("old", now.Add(-31*24*time.Hour))    // just past 30d
	insertAt("recent", now.Add(-1*time.Hour))     // well within retention
	insertAt("recent", now.Add(-29*24*time.Hour)) // just within 30d

	n, err := st.Prune(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Fatalf("Prune removed %d rows; want 2", n)
	}

	var remaining int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("remaining rows = %d; want 2", remaining)
	}

	var oldCount int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id = 'old'`).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("old-session rows remaining = %d; want 0", oldCount)
	}
}

func TestPruneNoOpWhenNothingOld(t *testing.T) {
	st := openTestStore(t)
	if err := st.InsertEvent("sess", "network", "info", Allow, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	n, err := st.Prune(30 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 0 {
		t.Fatalf("Prune removed %d rows; want 0 (nothing is old)", n)
	}
}

func openTestStore2(t *testing.T, path string) *Store {
	t.Helper()
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestListSessions(t *testing.T) {
	st := openTestStore(t)

	if err := st.InsertEvent("sess-a", "network", "info", Allow, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent("sess-a", "network", "high", Block, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent("sess-b", "git_push", "info", Allow, map[string]any{}); err != nil {
		t.Fatal(err)
	}

	sessions, err := st.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("ListSessions() returned %d sessions; want 2", len(sessions))
	}

	byID := map[string]SessionInfo{}
	for _, s := range sessions {
		byID[s.SessionID] = s
	}
	a, ok := byID["sess-a"]
	if !ok {
		t.Fatal("sess-a missing from ListSessions()")
	}
	if a.EventCount != 2 || a.Allow != 1 || a.Block != 1 {
		t.Fatalf("sess-a summary = %+v; want EventCount:2 Allow:1 Block:1", a)
	}
	if a.StartedAt.IsZero() || a.EndedAt.IsZero() {
		t.Fatalf("sess-a StartedAt/EndedAt not populated: %+v", a)
	}
}

func TestListEvents(t *testing.T) {
	st := openTestStore(t)

	if err := st.InsertEvent("sess-a", "network", "info", Allow, map[string]any{"host": "example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent("sess-a", "git_push", "high", Block, map[string]any{"remote": "evil.example/x"}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertEvent("sess-b", "network", "info", Allow, map[string]any{}); err != nil {
		t.Fatal(err)
	}

	events, err := st.ListEvents("sess-a")
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ListEvents(sess-a) returned %d events; want 2 (sess-b's event must not leak in)", len(events))
	}
	if events[0].Kind != "network" || events[1].Kind != "git_push" {
		t.Fatalf("ListEvents order = [%s, %s]; want chronological [network, git_push]", events[0].Kind, events[1].Kind)
	}
	if events[1].Decision != Block {
		t.Fatalf("events[1].Decision = %v; want Block", events[1].Decision)
	}
	if !strings.Contains(events[1].PayloadJSON, "evil.example/x") {
		t.Fatalf("events[1].PayloadJSON = %q; want it to contain the remote", events[1].PayloadJSON)
	}
}
