// Package policy implements the v0.1 Decide() step: a plain function, not a
// YAML rule engine (see ARCHITECTURE.md section 0.1/0.3 — YAML policy is
// explicitly deferred to v0.2).
package policy

import (
	"github.com/wang110696/Leash/internal/detect"
	"github.com/wang110696/Leash/internal/store"
)

// Decide turns detection findings into an allow/warn/block decision. v0.1's
// rule set is curated to be high-confidence, so any finding is sufficient
// to block — there is no confidence-combination logic yet (that belongs to
// the Target Architecture's Detect Pipeline, section 4.6).
func Decide(findings []detect.Finding) store.Decision {
	if len(findings) > 0 {
		return store.Block
	}
	return store.Allow
}
