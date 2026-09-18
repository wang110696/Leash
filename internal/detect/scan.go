// Package detect implements the detection rules (ARCHITECTURE.md section
// 0.6/10.1): a single Scan() function with rules written directly in
// code — no decoder registry, no pipeline abstraction. The rule set is
// deliberately restricted to specific, high-confidence token formats
// (known prefixes/structure), not generic high-entropy-string detection —
// that needs the multi-signal confidence scoring described as Target
// Architecture in ARCHITECTURE.md 4.6, which v0.1/v0.2 don't have yet, and
// a bare entropy check alone has an unacceptable false-positive rate
// (UUIDs, hashes, base64 image data, ...).
package detect

import "regexp"

// Finding is one detection hit. Confidence is fixed per-rule (no
// signal-combination scoring yet); rules are curated to be high-confidence
// on their own.
type Finding struct {
	Rule       string
	Confidence float64
}

// secretPatterns are specific, structured token formats — not generic
// entropy. Expanded in v0.2 beyond the original v0.1 quartet
// (OpenAI/Anthropic/GitHub/AWS) to cover a few more common services that
// are equally low-false-positive because they have a fixed, distinctive
// prefix or structure.
var secretPatterns = []struct {
	rule string
	re   *regexp.Regexp
}{
	{"openai_style_key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)},
	{"anthropic_style_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9-]{16,}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
	{"gitlab_pat", regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`)},
	{"aws_access_key_id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"slack_webhook_url", regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+`)},
	{"stripe_live_key", regexp.MustCompile(`[rs]k_live_[0-9A-Za-z]{20,}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"npm_token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	// A PEM private-key header is unambiguous — no legitimate reason for
	// this exact banner to appear in an outbound request body.
	{"private_key_pem", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
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
