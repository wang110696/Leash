// Package store persists events to a single local SQLite database. Per
// ARCHITECTURE.md section 0.8: one table, no seq, ordered by (ts, id).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id            INTEGER PRIMARY KEY,
	session_id    TEXT NOT NULL,
	ts            INTEGER NOT NULL,
	kind          TEXT NOT NULL,
	severity      TEXT NOT NULL,
	decision      TEXT NOT NULL,
	payload_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts, id);
`

type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and ensures
// the schema exists.
//
// The proxy process and every git-shim invocation open this same file
// independently, so concurrent writes are normal, not exceptional — without
// a busy timeout, modernc.org/sqlite fails a write immediately with
// "database is locked" on any overlap, which means an audited event can go
// silently unrecorded under completely ordinary concurrency (E4 in the v0.1
// security review). A generous busy_timeout makes SQLite retry internally
// instead.
func Open(path string) (*Store, error) {
	dsn := "file://" + path + "?_busy_timeout=5000"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Decision matches ARCHITECTURE.md's allow/warn/block vocabulary.
type Decision string

const (
	Allow Decision = "allow"
	Warn  Decision = "warn"
	Block Decision = "block"
)

// Summary reports how many events of each decision were recorded for a
// session — used for the end-of-session CLI banner. ProcessesObserved,
// DiffStatsRecorded and FileMutations are counted separately from Allow:
// process_exec (v0.2), git_diff_stat and file_mutation (v0.3) events are
// record-only informational enrichment, not allow/block decisions about a
// security-sensitive action, and mixing them into Allow would make that
// count misleading.
type Summary struct {
	Allow, Warn, Block int
	ProcessesObserved  int
	DiffStatsRecorded  int
	FileMutations      int
}

func (s *Store) Summary(sessionID string) (Summary, error) {
	rows, err := s.db.Query(
		`SELECT decision, kind, COUNT(*) FROM events WHERE session_id = ? GROUP BY decision, kind`,
		sessionID)
	if err != nil {
		return Summary{}, err
	}
	defer rows.Close()

	var sum Summary
	for rows.Next() {
		var decision, kind string
		var n int
		if err := rows.Scan(&decision, &kind, &n); err != nil {
			return Summary{}, err
		}
		switch kind {
		case "process_exec":
			sum.ProcessesObserved += n
			continue
		case "git_diff_stat":
			sum.DiffStatsRecorded += n
			continue
		case "file_mutation":
			sum.FileMutations += n
			continue
		}
		switch Decision(decision) {
		case Allow:
			sum.Allow += n
		case Warn:
			sum.Warn += n
		case Block:
			sum.Block += n
		}
	}
	return sum, rows.Err()
}

// InsertEvent records one event. payload must not contain raw secrets or
// raw request/diff bodies — only fingerprints and metadata
// (ARCHITECTURE.md section 0.8).
func (s *Store) InsertEvent(sessionID, kind, severity string, decision Decision, payload any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO events (session_id, ts, kind, severity, decision, payload_json) VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, time.Now().UnixMilli(), kind, severity, string(decision), string(buf),
	)
	return err
}

// Event is one row of the events table, as read back for display
// (ARCHITECTURE.md 10.1 v0.3 "flight recorder" dashboard).
type Event struct {
	ID          int64
	SessionID   string
	Ts          time.Time
	Kind        string
	Severity    string
	Decision    Decision
	PayloadJSON string
}

// SessionInfo summarizes one session for the dashboard's session list.
type SessionInfo struct {
	SessionID  string
	StartedAt  time.Time
	EndedAt    time.Time
	EventCount int
	Allow      int
	Warn       int
	Block      int
}

// ListSessions returns every session that has at least one event, most
// recently active first.
func (s *Store) ListSessions() ([]SessionInfo, error) {
	rows, err := s.db.Query(`
		SELECT session_id, MIN(ts), MAX(ts), COUNT(*),
		       SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN decision = 'warn'  THEN 1 ELSE 0 END),
		       SUM(CASE WHEN decision = 'block' THEN 1 ELSE 0 END)
		FROM events
		GROUP BY session_id
		ORDER BY MAX(ts) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionInfo
	for rows.Next() {
		var info SessionInfo
		var startMs, endMs int64
		if err := rows.Scan(&info.SessionID, &startMs, &endMs, &info.EventCount,
			&info.Allow, &info.Warn, &info.Block); err != nil {
			return nil, err
		}
		info.StartedAt = time.UnixMilli(startMs)
		info.EndedAt = time.UnixMilli(endMs)
		out = append(out, info)
	}
	return out, rows.Err()
}

// ListEvents returns every event for a session in chronological order
// (the session's "replay" — ARCHITECTURE.md 10.1 v0.3).
func (s *Store) ListEvents(sessionID string) ([]Event, error) {
	rows, err := s.db.Query(
		`SELECT id, session_id, ts, kind, severity, decision, payload_json
		 FROM events WHERE session_id = ? ORDER BY ts, id`,
		sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var tsMs int64
		var decision string
		if err := rows.Scan(&e.ID, &e.SessionID, &tsMs, &e.Kind, &e.Severity, &decision, &e.PayloadJSON); err != nil {
			return nil, err
		}
		e.Ts = time.UnixMilli(tsMs)
		e.Decision = Decision(decision)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Prune deletes events older than olderThan and returns how many rows were
// removed (ARCHITECTURE.md 5.1/10.1 "retention"). It runs an unconditional
// VACUUM afterward so disk usage actually shrinks — SQLite doesn't release
// freed pages back to the filesystem on its own.
func (s *Store) Prune(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return n, err
	}
	if n > 0 {
		if _, err := s.db.Exec(`VACUUM`); err != nil {
			return n, err
		}
	}
	return n, nil
}
