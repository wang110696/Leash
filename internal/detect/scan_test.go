package detect

import "testing"

func hasRule(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestScanSecretPatterns(t *testing.T) {
	cases := []struct {
		name string
		body string
		rule string
	}{
		{"openai key", "here is my key sk-abcdefghijklmnopqrstuvwxyz012345", "openai_style_key"},
		{"anthropic key", "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop", "anthropic_style_key"},
		{"github token", "auth: ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github_token"},
		{"aws key", "aws_access_key_id = AKIAABCDEFGHIJKLMNOP", "aws_access_key_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := Scan([]byte(tc.body))
			if !hasRule(findings, tc.rule) {
				t.Fatalf("Scan(%q) = %+v; want a finding for rule %q", tc.body, findings, tc.rule)
			}
		})
	}
}

func TestScanDotenvPattern(t *testing.T) {
	body := "DATABASE_URL=postgres://user:pass@localhost/db\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789\n"
	findings := Scan([]byte(body))
	if !hasRule(findings, "dotenv_pattern") {
		t.Fatalf("Scan(%q) = %+v; want dotenv_pattern finding", body, findings)
	}
}

func TestScanSingleEnvLineDoesNotTriggerDotenvPattern(t *testing.T) {
	// The dotenv heuristic requires >=2 KEY=value lines; a single one
	// (common in ordinary form posts, e.g. a single form field) shouldn't
	// be flagged on its own — that would be a false positive that erodes
	// trust in the tool (see the "entropy is a signal, not a verdict"
	// design principle in ARCHITECTURE.md).
	body := "SOME_FIELD=some_value"
	findings := Scan([]byte(body))
	if hasRule(findings, "dotenv_pattern") {
		t.Fatalf("Scan(%q) = %+v; did not expect dotenv_pattern from a single KEY=value line", body, findings)
	}
}

func TestScanBenignBody(t *testing.T) {
	body := `{"message":"hello world","id":42}`
	findings := Scan([]byte(body))
	if len(findings) != 0 {
		t.Fatalf("Scan(%q) = %+v; want no findings for benign JSON body", body, findings)
	}
}

func TestScanEmptyBody(t *testing.T) {
	if findings := Scan(nil); len(findings) != 0 {
		t.Fatalf("Scan(nil) = %+v; want no findings", findings)
	}
	if findings := Scan([]byte{}); len(findings) != 0 {
		t.Fatalf("Scan([]byte{}) = %+v; want no findings", findings)
	}
}
