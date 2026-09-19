package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wang110696/Leash/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// waitForEvents polls the store until at least min file_mutation events
// exist for sessionID, or timeout elapses. fsnotify delivery is
// asynchronous, so tests poll rather than sleep-and-hope.
func waitForEvents(t *testing.T, st *store.Store, sessionID string, min int, timeout time.Duration) []store.Event {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		events, err := st.ListEvents(sessionID)
		if err != nil {
			t.Fatal(err)
		}
		var mutations []store.Event
		for _, e := range events {
			if e.Kind == "file_mutation" {
				mutations = append(mutations, e)
			}
		}
		if len(mutations) >= min || time.Now().After(deadline) {
			return mutations
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWatcher_RecordsFileWrite(t *testing.T) {
	root := t.TempDir()
	st := testStore(t)

	w, err := New("sess1", root, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	events := waitForEvents(t, st, "sess1", 1, 3*time.Second)
	if len(events) == 0 {
		t.Fatal("no file_mutation event recorded for a new file write")
	}
	if !contains(events, "hello.txt") {
		t.Fatalf("no event mentions hello.txt: %+v", events)
	}
}

func TestWatcher_ExcludesGitDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	st := testStore(t)

	w, err := New("sess1", root, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	// Something outside .git, to give the watcher time to see it (and
	// prove the watcher itself is working) alongside the excluded write.
	if err := os.WriteFile(filepath.Join(root, ".git", "objects", "secret-blob"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	events := waitForEvents(t, st, "sess1", 1, 3*time.Second)
	if contains(events, "objects") || contains(events, "secret-blob") {
		t.Fatalf(".git directory contents were not excluded: %+v", events)
	}
	if !contains(events, "tracked.txt") {
		t.Fatalf("expected the non-excluded file to be recorded: %+v", events)
	}
}

func TestWatcher_CapsEvents(t *testing.T) {
	const eventCap = 3
	orig := MaxEventsPerSession
	MaxEventsPerSession = eventCap

	root := t.TempDir()
	st := testStore(t)

	w, err := New("sess1", root, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("file%d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Give the watcher time to process everything it's going to process;
	// there's no "at least" signal to poll for here since we expect it to
	// stop recording, so a bounded wait is the best available check.
	time.Sleep(500 * time.Millisecond)

	// Stop the watcher goroutine and wait for it to actually exit — via a
	// channel close, which is a proper happens-before edge — before
	// touching the shared MaxEventsPerSession var again. Restoring it
	// while Run()'s goroutine might still be reading it is exactly the
	// kind of race `go test -race` exists to catch.
	cancel()
	<-done
	MaxEventsPerSession = orig

	events, err := st.ListEvents("sess1")
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, e := range events {
		if e.Kind == "file_mutation" {
			n++
		}
	}
	if n > eventCap {
		t.Fatalf("recorded %d file_mutation events; want at most the cap of %d", n, eventCap)
	}
}

func contains(events []store.Event, substr string) bool {
	for _, e := range events {
		if strings.Contains(e.PayloadJSON, substr) {
			return true
		}
	}
	return false
}
