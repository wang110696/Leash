package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// knownRemotesFile holds the snapshot of normalized remote identities
// (gitremote.Normalize output) captured at session start. The Git Sensor
// compares push destinations against this baseline (ARCHITECTURE.md 5.5).
const knownRemotesFile = "known_remotes.json"

// SaveKnownRemotes writes the session's baseline remote snapshot.
func SaveKnownRemotes(sessionDir string, remotes []string) error {
	buf, err := json.Marshal(remotes)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sessionDir, knownRemotesFile), buf, 0o600)
}

// LoadKnownRemotes reads back the session's baseline remote snapshot. A
// missing or unreadable file is treated as a hard error by the caller —
// the git shim fails closed on push when it can't confirm the baseline
// (ARCHITECTURE.md 0.7).
func LoadKnownRemotes(sessionDir string) ([]string, error) {
	buf, err := os.ReadFile(filepath.Join(sessionDir, knownRemotesFile))
	if err != nil {
		return nil, fmt.Errorf("read known remotes snapshot: %w", err)
	}
	var remotes []string
	if err := json.Unmarshal(buf, &remotes); err != nil {
		return nil, fmt.Errorf("parse known remotes snapshot: %w", err)
	}
	return remotes, nil
}
