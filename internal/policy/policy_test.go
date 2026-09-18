package policy

import (
	"testing"

	"github.com/wang110696/Leash/internal/detect"
	"github.com/wang110696/Leash/internal/store"
)

func TestDecide(t *testing.T) {
	if got := Decide(nil); got != store.Allow {
		t.Errorf("Decide(nil) = %v; want Allow", got)
	}
	if got := Decide([]detect.Finding{}); got != store.Allow {
		t.Errorf("Decide([]) = %v; want Allow", got)
	}
	findings := []detect.Finding{{Rule: "openai_style_key", Confidence: 0.95}}
	if got := Decide(findings); got != store.Block {
		t.Errorf("Decide(%v) = %v; want Block", findings, got)
	}
}
