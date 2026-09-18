// Package internal defines the Session type shared by the proxy, git shim,
// and store. See ARCHITECTURE.md section 0.1: this is a struct, not an
// interface/abstraction — v0.1 only has one Session Provider (Launch).
package internal

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Session is the logical execution boundary for one `leash run` invocation.
type Session struct {
	ID          string
	Command     []string
	RepoPath    string
	ProxyAddr   string // 127.0.0.1:<port>, kernel-assigned
	RealGitPath string // resolved via exec.LookPath BEFORE PATH is modified
	Dir         string // ~/.leash/sessions/<id>, holds state + shim binary
	StartedAt   time.Time
}

// NewSessionID returns a short random hex identifier for a session.
func NewSessionID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
