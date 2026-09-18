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
// session — used for the end-of-session CLI banner. ProcessesObserved is
// counted separately from Allow: process_exec events (Runtime Sensor ·
// Process Plane, v0.2) are record-only informational events, not
// allow/block decisions about a security-sensitive action, and mixing
// them into Allow would make that count misleading.
type Summary struct {
	Allow, Warn, Block int
	ProcessesObserved  int
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
		if kind == "process_exec" {
			sum.ProcessesObserved += n
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
