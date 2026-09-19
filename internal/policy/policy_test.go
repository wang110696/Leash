package policy

import (
	"testing"
	"time"

	"github.com/wang110696/Leash/internal/store"
)

func TestDefaultDecide(t *testing.T) {
	cfg := Default()

	if got, _ := cfg.Decide(nil, Request{Host: "example.com"}); got != store.Allow {
		t.Errorf("Default().Decide(nil) = %v; want Allow", got)
	}
	findings := []Finding{{Rule: "openai_style_key", Confidence: 0.95}}
	if got, _ := cfg.Decide(findings, Request{Host: "example.com"}); got != store.Block {
		t.Errorf("Default().Decide(%v) = %v; want Block (v0.1-compatible: unlisted rule defaults to block)", findings, got)
	}
}

func TestDenyDomains(t *testing.T) {
	cfg := &Config{Egress: EgressConfig{DenyDomains: []string{"evil.example"}}}

	got, _ := cfg.Decide(nil, Request{Host: "evil.example"})
	if got != store.Block {
		t.Errorf("host in deny_domains: Decide = %v; want Block", got)
	}
	// subdomain should also match
	got, _ = cfg.Decide(nil, Request{Host: "api.evil.example"})
	if got != store.Block {
		t.Errorf("subdomain of deny_domains entry: Decide = %v; want Block", got)
	}
	got, _ = cfg.Decide(nil, Request{Host: "fine.example"})
	if got != store.Allow {
		t.Errorf("host not in deny_domains: Decide = %v; want Allow", got)
	}
}

func TestAllowDomainsAllowlistMode(t *testing.T) {
	cfg := &Config{Egress: EgressConfig{AllowDomains: []string{"api.openai.com", "github.com"}}}

	got, _ := cfg.Decide(nil, Request{Host: "api.openai.com"})
	if got != store.Allow {
		t.Errorf("host in allow_domains: Decide = %v; want Allow", got)
	}
	got, _ = cfg.Decide(nil, Request{Host: "evil.example"})
	if got != store.Block {
		t.Errorf("host not in allow_domains (allowlist mode): Decide = %v; want Block", got)
	}
}

func TestRuleActionOverride(t *testing.T) {
	cfg := &Config{Egress: EgressConfig{Rules: map[string]string{
		"dotenv_pattern": "warn",
	}}}

	findings := []Finding{{Rule: "dotenv_pattern"}}
	got, _ := cfg.Decide(findings, Request{Host: "example.com"})
	if got != store.Warn {
		t.Errorf("overridden rule action: Decide = %v; want Warn", got)
	}

	// A rule not mentioned in Rules still defaults to block.
	findings = []Finding{{Rule: "openai_style_key"}}
	got, _ = cfg.Decide(findings, Request{Host: "example.com"})
	if got != store.Block {
		t.Errorf("unlisted rule: Decide = %v; want Block", got)
	}
}

func TestGitHubActionPolicy(t *testing.T) {
	t.Run("deny_actions blocks gist creation", func(t *testing.T) {
		cfg := &Config{GitHub: GitHubConfig{DenyActions: []string{"create_gist"}}}
		got, reason := cfg.Decide(nil, Request{Host: "api.github.com", Method: "POST", Path: "/gists"})
		if got != store.Block {
			t.Errorf("gist creation with create_gist denied: Decide = %v (%s); want Block", got, reason)
		}
	})

	t.Run("repo creation outside allowed_orgs is blocked", func(t *testing.T) {
		cfg := &Config{GitHub: GitHubConfig{AllowedOrgs: []string{"my-company"}}}
		got, _ := cfg.Decide(nil, Request{Host: "api.github.com", Method: "POST", Path: "/orgs/attacker-org/repos"})
		if got != store.Block {
			t.Errorf("repo creation outside allowed_orgs: Decide = %v; want Block", got)
		}
	})

	t.Run("repo creation inside allowed_orgs is allowed", func(t *testing.T) {
		cfg := &Config{GitHub: GitHubConfig{AllowedOrgs: []string{"my-company"}}}
		got, _ := cfg.Decide(nil, Request{Host: "api.github.com", Method: "POST", Path: "/orgs/my-company/repos"})
		if got != store.Allow {
			t.Errorf("repo creation inside allowed_orgs: Decide = %v; want Allow", got)
		}
	})

	t.Run("personal repo creation is unaffected by allowed_orgs", func(t *testing.T) {
		cfg := &Config{GitHub: GitHubConfig{AllowedOrgs: []string{"my-company"}}}
		got, _ := cfg.Decide(nil, Request{Host: "api.github.com", Method: "POST", Path: "/user/repos"})
		if got != store.Block {
			t.Errorf("personal repo creation with allowed_orgs set: Decide = %v; want Block (no org to check against)", got)
		}
	})

	t.Run("unrelated github.com traffic is untouched", func(t *testing.T) {
		cfg := &Config{GitHub: GitHubConfig{DenyActions: []string{"create_gist"}}}
		got, _ := cfg.Decide(nil, Request{Host: "api.github.com", Method: "GET", Path: "/user"})
		if got != store.Allow {
			t.Errorf("unrelated GET request: Decide = %v; want Allow", got)
		}
	})
}

func TestLoadMissingFileReturnsDefault(t *testing.T) {
	cfg, err := Load("/nonexistent/path/policy.yaml")
	if err != nil {
		t.Fatalf("Load(missing) error: %v", err)
	}
	if len(cfg.Egress.AllowDomains) != 0 || len(cfg.Egress.DenyDomains) != 0 {
		t.Fatalf("Load(missing) = %+v; want the zero-value Default()", cfg)
	}
}

func TestRetentionDuration(t *testing.T) {
	if got := (RetentionConfig{}).Duration(); got != 30*24*time.Hour {
		t.Errorf("zero-value RetentionConfig.Duration() = %v; want 30 days default", got)
	}
	if got := (RetentionConfig{Days: 7}).Duration(); got != 7*24*time.Hour {
		t.Errorf("RetentionConfig{Days:7}.Duration() = %v; want 7 days", got)
	}
	if got := (RetentionConfig{Days: -5}).Duration(); got != 30*24*time.Hour {
		t.Errorf("negative Days should fall back to default: got %v", got)
	}
}
