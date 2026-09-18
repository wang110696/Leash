// Config is the v0.2 YAML policy engine, reintroduced after being cut from
// v0.1 to keep the first demo small (ARCHITECTURE.md section 0.1/10.1).
// It adds domain-level allow/deny and a github.com-specific "destination
// allowed ≠ action safe" check (ARCHITECTURE.md 8.3) on top of the fixed
// v0.1 rule-name → action mapping.
package policy

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wang110696/Leash/internal/store"
)

// Config is the parsed policy. The zero value (from Default()) reproduces
// v0.1's behavior exactly: any detect.Finding blocks, no domain
// restrictions, no GitHub action restrictions — so a session with no
// policy file behaves identically to before this feature existed.
type Config struct {
	Egress EgressConfig `yaml:"egress"`
	GitHub GitHubConfig `yaml:"github"`
}

type EgressConfig struct {
	// AllowDomains, if non-empty, switches to allowlist mode: only these
	// domains (and their subdomains) may be contacted at all, regardless
	// of content. Empty means no domain restriction — decisions are
	// content-based only, matching v0.1.
	AllowDomains []string `yaml:"allow_domains"`
	// DenyDomains are blocked outright, before content is even
	// considered.
	DenyDomains []string `yaml:"deny_domains"`
	// Rules maps a detect.Finding rule name to an action
	// ("allow"/"warn"/"block"). A rule not listed here defaults to
	// "block" — the v0.1 rule set is curated to be high-confidence, so
	// silence should not mean "let it through."
	Rules map[string]string `yaml:"rules"`
}

type GitHubConfig struct {
	// AllowedOrgs, if non-empty, restricts repo creation (via the GitHub
	// API) to these orgs — allowing github.com as a destination doesn't
	// mean every action on it is safe (ARCHITECTURE.md 8.3): an agent can
	// create a repo outside the company org just as easily as pushing to
	// one that exists.
	AllowedOrgs []string `yaml:"allowed_orgs"`
	// DenyActions blocks specific GitHub API actions outright regardless
	// of org, e.g. "create_gist" (gists are public-by-default sharing,
	// arguably never appropriate for an unattended agent to create).
	DenyActions []string `yaml:"deny_actions"`
}

// Default returns the policy v0.1 always used: block on any finding, no
// domain or GitHub restrictions.
func Default() *Config {
	return &Config{}
}

// Load reads and parses a policy file. A missing file is not an error —
// it returns Default() so `leash run` works with zero configuration, the
// same as v0.1.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Request carries the request metadata Decide needs beyond the content
// findings — just enough for domain and GitHub-action policy, not a
// general-purpose HTTP request model.
type Request struct {
	Host   string
	Method string
	Path   string
}

// Decide is the v0.2 policy decision: domain rules and the GitHub action
// check are evaluated first (they can block regardless of content), then
// content findings are mapped through Rules.
func (c *Config) Decide(findings []Finding, req Request) (decision store.Decision, reason string) {
	host := strings.ToLower(req.Host)
	if host == "" {
		host = req.Host
	}
	// Host may include ":port" (as seen on the wire); strip it for domain
	// matching.
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}

	if matchesAny(host, c.Egress.DenyDomains) {
		return store.Block, "domain in deny_domains"
	}
	if len(c.Egress.AllowDomains) > 0 && !matchesAny(host, c.Egress.AllowDomains) {
		return store.Block, "domain not in allow_domains"
	}

	if action := githubAction(host, req.Method, req.Path); action != "" {
		if containsFold(c.GitHub.DenyActions, action) {
			return store.Block, "github action denied: " + action
		}
		if action == "create_repo" && len(c.GitHub.AllowedOrgs) > 0 {
			org := githubRepoOrg(req.Path)
			if org == "" || !containsFold(c.GitHub.AllowedOrgs, org) {
				return store.Block, "github repo creation outside allowed_orgs"
			}
		}
	}

	worst := store.Allow
	worstReason := ""
	for _, f := range findings {
		action := c.actionFor(f.Rule)
		if severityRank(action) > severityRank(worst) {
			worst = action
			worstReason = "matched rule: " + f.Rule
		}
	}
	return worst, worstReason
}

// Finding mirrors detect.Finding's shape without importing the detect
// package here, avoiding a policy<->detect import cycle risk as both
// packages grow; internal/proxy, which imports both, does the conversion.
type Finding struct {
	Rule       string
	Confidence float64
}

func (c *Config) actionFor(rule string) store.Decision {
	if c.Egress.Rules != nil {
		if a, ok := c.Egress.Rules[rule]; ok {
			switch strings.ToLower(a) {
			case "allow":
				return store.Allow
			case "warn":
				return store.Warn
			case "block":
				return store.Block
			}
		}
	}
	// Unlisted rule: v0.1-compatible default is block (see Rules doc
	// comment above).
	return store.Block
}

func severityRank(d store.Decision) int {
	switch d {
	case store.Block:
		return 2
	case store.Warn:
		return 1
	default:
		return 0
	}
}

func matchesAny(host string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// githubAction recognizes a small, explicit set of GitHub REST API
// endpoints that create world-visible artifacts. It's deliberately narrow
// (path string matching, not a GitHub API client) — the point is to
// demonstrate that "allowed domain" and "allowed action" are different
// policy dimensions (ARCHITECTURE.md 8.3), not to fully model the GitHub
// API surface.
func githubAction(host, method, path string) string {
	if host != "api.github.com" || method != "POST" {
		return ""
	}
	switch {
	case path == "/gists":
		return "create_gist"
	case path == "/user/repos":
		return "create_repo"
	case strings.HasPrefix(path, "/orgs/") && strings.HasSuffix(path, "/repos"):
		return "create_repo"
	}
	return ""
}

// githubRepoOrg extracts the org name from an org-scoped repo-creation
// path ("/orgs/<org>/repos"). Personal repo creation ("/user/repos") has
// no org, so it returns "".
func githubRepoOrg(path string) string {
	const prefix = "/orgs/"
	const suffix = "/repos"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
}
