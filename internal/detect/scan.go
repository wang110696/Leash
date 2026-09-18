// Package detect implements the v0.1 detection rules. Per ARCHITECTURE.md
// section 0.6, this is a single Scan() function with rules written directly
// in code — no decoder registry, no pipeline abstraction.
package detect

import "regexp"

// Finding is one detection hit. Confidence is fixed per-rule in v0.1 (no
// signal combination yet); rules are curated to be high-confidence.
type Finding struct {
	Rule       string
	Confidence float64
}

var secretPatterns = []struct {
	rule string
	re   *regexp.Regexp
}{
	{"openai_style_key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"anthropic_style_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9-]{16,}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
	{"aws_access_key_id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
}

// dotenvLine matches a typical `KEY=value` line as found in .env files.
var dotenvLine = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]*=\S+$`)

// Scan runs the fixed v0.1 rule set against a byte payload (an HTTP request
// body, or similar). It never returns a partial/incomplete result silently —
// on internal error it panics, and callers are expected to treat that as a
// block decision per the fail-closed invariant (ARCHITECTURE.md 0.7/0.9).
func Scan(data []byte) []Finding {
	var findings []Finding

	for _, p := range secretPatterns {
		if p.re.Match(data) {
			findings = append(findings, Finding{Rule: p.rule, Confidence: 0.95})
		}
	}

	if n := len(dotenvLine.FindAll(data, -1)); n >= 2 {
		findings = append(findings, Finding{Rule: "dotenv_pattern", Confidence: 0.8})
	}

	return findings
}
