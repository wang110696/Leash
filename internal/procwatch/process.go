// Package procwatch implements the v0.2 Runtime Sensor · Process Plane and
// a first cut of the Attribution Engine (ARCHITECTURE.md 4.2/5.2/10.1).
//
// This is explicitly best-effort and record-only — it never blocks
// anything, only records what it sees. macOS's real process-execution
// primitive (EndpointSecurity) requires an entitlement, a System
// Extension, and a full signing/notarization pipeline (ARCHITECTURE.md
// 6.1) — that's the separate Platform Enforcement Track, not something a
// userspace Go binary can do. What's achievable in v0.2's Core Track is
// periodic polling of the process table via `ps`, diffed against the
// previous snapshot to notice new processes, with attribution to the
// session by walking each new process's parent-PID chain back to the
// session's root process.
//
// Known limitations, stated up front rather than discovered later:
//   - A process that starts and exits entirely between two polls is
//     invisible — this is fundamentally a sampling approach, not an event
//     stream. Shorten the poll interval to reduce (never eliminate) this.
//   - Ancestry-based attribution has the same blind spot documented in
//     ARCHITECTURE.md 7.2/8: a process delegated to something that
//     already existed before the session (a running browser, a running
//     Docker daemon) is not a descendant of the session root and will not
//     be attributed, correctly reflecting "we don't know" rather than
//     guessing.
package procwatch

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/wang110696/Leash/internal/store"
)

// DefaultPollInterval balances catching short-lived processes against the
// overhead of shelling out to `ps` repeatedly.
const DefaultPollInterval = 300 * time.Millisecond

// Observer polls the process table and attributes new processes to a
// session by ancestry.
type Observer struct {
	sessionID    string
	st           *store.Store
	pollInterval time.Duration

	// sessionPIDs is the set of PIDs known to belong to this session's
	// process tree, seeded with the root (launched agent) PID.
	sessionPIDs map[int]bool
}

// New creates an Observer for the process tree rooted at rootPID (the
// agent process `leash run` just launched).
func New(sessionID string, rootPID int, st *store.Store) *Observer {
	return &Observer{
		sessionID:    sessionID,
		st:           st,
		pollInterval: DefaultPollInterval,
		sessionPIDs:  map[int]bool{rootPID: true},
	}
}

// Run polls until ctx is cancelled. Intended to be run in its own
// goroutine for the lifetime of the session.
func (o *Observer) Run(ctx context.Context) {
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.poll()
		}
	}
}

func (o *Observer) poll() {
	procs, err := snapshot()
	if err != nil {
		// Best-effort: a failed poll just means we miss this interval, not
		// a session-ending error. Process Plane visibility gaps are an
		// accepted, documented limitation (see package doc).
		return
	}
	o.pollProcs(procs)
}

// pollProcs is the snapshot-independent half of poll(), split out so tests
// can drive it with a synthetic process table instead of the real `ps`.
func (o *Observer) pollProcs(procs map[int]procInfo) {
	for _, p := range attribute(o.sessionPIDs, procs) {
		o.record(p)
	}
}

// attribute mutates sessionPIDs in place, adding every process in procs
// that's a descendant (by ancestry chain) of an already-known session PID,
// and returns the newly attributed processes in the order they were found.
//
// It sweeps repeatedly until a full pass adds nothing new, so a process
// whose parent was itself only just added this same poll (e.g. a
// grandchild spawned in the same tick) is still caught within one cycle
// instead of waiting for the next poll.
func attribute(sessionPIDs map[int]bool, procs map[int]procInfo) []procInfo {
	var newlyAttributed []procInfo
	for {
		addedAny := false
		for pid, proc := range procs {
			if sessionPIDs[pid] {
				continue
			}
			if sessionPIDs[proc.ppid] {
				sessionPIDs[pid] = true
				newlyAttributed = append(newlyAttributed, proc)
				addedAny = true
			}
		}
		if !addedAny {
			break
		}
	}
	return newlyAttributed
}

func (o *Observer) record(p procInfo) {
	if err := o.st.InsertEvent(o.sessionID, "process_exec", "info", store.Allow, map[string]any{
		"pid":  p.pid,
		"ppid": p.ppid,
		"comm": p.comm,
		// Full argv is deliberately not captured yet: command-line
		// arguments routinely carry secrets (e.g. `curl -H "Authorization:
		// Bearer sk-..."`), and storing them without the same redaction
		// discipline applied to network/git events (ARCHITECTURE.md
		// 0.8/0.9, E5) would quietly reopen that hole. Comm-only for now.
		"attribution": "process_ancestry",
	}); err != nil {
		fmt.Fprintf(os.Stderr, "leash: failed to record process_exec event: %v\n", err)
	}
}

type procInfo struct {
	pid, ppid int
	comm      string
}

// snapshot lists every process visible to the current user via `ps`,
// which on macOS is exactly this user's own processes without needing
// elevated privileges — sufficient for attributing the session's own
// descendants.
func snapshot() (map[int]procInfo, error) {
	cmd := exec.Command("ps", "-axo", "pid=,ppid=,comm=")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	procs := make(map[int]procInfo)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		procs[pid] = procInfo{pid: pid, ppid: ppid, comm: strings.Join(fields[2:], " ")}
	}
	return procs, sc.Err()
}
