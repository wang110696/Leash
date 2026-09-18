package store

import (
	"path/filepath"
	"testing"
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

func openTestStore2(t *testing.T, path string) *Store {
	t.Helper()
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
