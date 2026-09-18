package detect

import (
	"strings"
	"testing"
)

func hasRule(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// join builds a test fixture from parts at runtime, rather than as a
// single string literal in the source. These are synthetic values used
// only to exercise our own regexes — never real credentials — but a
// complete, syntactically-valid-looking secret sitting in the source text
// is exactly what GitHub's (and other) push-protection secret scanners
// look for, and they scan source bytes, not runtime values. Splitting the
// literal avoids that false positive without weakening the test.
func join(parts ...string) string { return strings.Join(parts, "") }

func TestScanSecretPatterns(t *testing.T) {
	cases := []struct {
		name string
		body string
		rule string
	}{
		{"openai key", join("here is my key ", "sk-", "abcdefghijklmnopqrstuvwxyz012345"), "openai_style_key"},
		{"anthropic key", join("ANTHROPIC_API_KEY=", "sk-ant-api03-", "abcdefghijklmnop"), "anthropic_style_key"},
		{"github token", join("auth: ", "ghp_", "abcdefghijklmnopqrstuvwxyz0123456789"), "github_token"},
		{"aws key", join("aws_access_key_id = ", "AKIA", "ABCDEFGHIJKLMNOP"), "aws_access_key_id"},
		{"gitlab pat", join("token: ", "glpat-", "abcdefghijklmnopqrst"), "gitlab_pat"},
		{"slack bot token", join("SLACK_TOKEN=", "xoxb-1234567890-", "abcdefghij"), "slack_token"},
		{"slack webhook", join("https://hooks.slack.com/services/", "T00000000/B00000000/", "XXXXXXXXXXXXXXXXXXXXXXXX"), "slack_webhook_url"},
		{"stripe live key", join("sk", "_live_", "abcdefghijklmnopqrstuvwx"), "stripe_live_key"},
		{"google api key", join("AIza", "SyD-abcdefghijklmnopqrstuvwxyz012345"), "google_api_key"},
		{"npm token", join("//registry.npmjs.org/:_authToken=", "npm_", "abcdefghijklmnopqrstuvwxyz0123456789"), "npm_token"},
		{"rsa private key", join("-----BEGIN RSA PRIVATE KEY-----", "\nMIIB...\n", "-----END RSA PRIVATE KEY-----"), "private_key_pem"},
		{"generic private key", join("-----BEGIN PRIVATE KEY-----", "\nMIIB...\n", "-----END PRIVATE KEY-----"), "private_key_pem"},
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
	body := join("DATABASE_URL=postgres://user:pass@localhost/db\nOPENAI_API_KEY=", "sk-proj-", "abcdefghijklmnopqrstuvwxyz0123456789\n")
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
