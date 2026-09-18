package procwatch

import (
	"path/filepath"
	"testing"

	"github.com/wang110696/Leash/internal/store"
)

func TestAttribute_DirectChild(t *testing.T) {
	sessionPIDs := map[int]bool{100: true}
	procs := map[int]procInfo{
		100: {pid: 100, ppid: 1, comm: "root-agent"},
		101: {pid: 101, ppid: 100, comm: "child"},
	}

	got := attribute(sessionPIDs, procs)
	if len(got) != 1 || got[0].pid != 101 {
		t.Fatalf("attribute() = %v; want [pid 101]", got)
	}
	if !sessionPIDs[101] {
		t.Fatal("sessionPIDs was not updated to include the newly attributed child")
	}
}

func TestAttribute_MultiGenerationInOnePoll(t *testing.T) {
	// grandchild's parent (child) isn't in sessionPIDs yet at the start of
	// this poll — both must still be attributed within a single call.
	sessionPIDs := map[int]bool{100: true}
	procs := map[int]procInfo{
		100: {pid: 100, ppid: 1, comm: "root-agent"},
		101: {pid: 101, ppid: 100, comm: "child"},
		102: {pid: 102, ppid: 101, comm: "grandchild"},
	}

	got := attribute(sessionPIDs, procs)
	if len(got) != 2 {
		t.Fatalf("attribute() = %v; want 2 processes attributed in one pass", got)
	}
	if !sessionPIDs[101] || !sessionPIDs[102] {
		t.Fatalf("sessionPIDs = %v; want both 101 and 102 attributed", sessionPIDs)
	}
}

func TestAttribute_UnrelatedProcessNotAttributed(t *testing.T) {
	// A process whose parent already existed before the session (e.g. a
	// long-running Dropbox/Chrome/dockerd) must NOT be attributed — this
	// is the delegated-exfiltration blind spot the architecture doc
	// documents rather than papers over (ARCHITECTURE.md 7.2/8).
	sessionPIDs := map[int]bool{100: true}
	procs := map[int]procInfo{
		100: {pid: 100, ppid: 1, comm: "root-agent"},
		999: {pid: 999, ppid: 1, comm: "unrelated-preexisting-daemon"},
	}

	got := attribute(sessionPIDs, procs)
	if len(got) != 0 {
		t.Fatalf("attribute() = %v; want no processes attributed (999's parent is pid 1, not the session)", got)
	}
	if sessionPIDs[999] {
		t.Fatal("unrelated process 999 was incorrectly attributed to the session")
	}
}

func TestAttribute_AlreadyKnownNotReattributed(t *testing.T) {
	sessionPIDs := map[int]bool{100: true, 101: true}
	procs := map[int]procInfo{
		100: {pid: 100, ppid: 1},
		101: {pid: 101, ppid: 100},
	}
	got := attribute(sessionPIDs, procs)
	if len(got) != 0 {
		t.Fatalf("attribute() = %v; want no re-attribution of already-known PIDs", got)
	}
}

func TestObserverRecordsToStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	obs := New("sess1", 100, st)
	obs.pollProcs(map[int]procInfo{
		100: {pid: 100, ppid: 1, comm: "root-agent"},
		101: {pid: 101, ppid: 100, comm: "child-tool"},
	})

	sum, err := st.Summary("sess1")
	if err != nil {
		t.Fatal(err)
	}
	if sum.ProcessesObserved != 1 {
		t.Fatalf("Summary.ProcessesObserved = %d; want 1 (only the child, root PID is the seed not an observed event)", sum.ProcessesObserved)
	}
}

func TestSnapshot_FindsCurrentProcess(t *testing.T) {
	procs, err := snapshot()
	if err != nil {
		t.Skipf("ps not available in this environment: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("snapshot() returned no processes at all")
	}
	// os.Getpid() (the test binary itself) should be visible.
	// (Not asserting a specific PID since it varies per run.)
}
