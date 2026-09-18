// Package gitremote normalizes git remote URLs to a comparable identity
// (scheme + host + org/repo), per ARCHITECTURE.md section 5.5: risk
// judgment must not rely on the remote's local name (e.g. "origin") since
// that can be silently repointed.
package gitremote

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// scpLike matches the SSH shorthand form: user@host:path (e.g.
// git@github.com:org/repo.git), as opposed to an explicit ssh:// URL.
var scpLike = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)

// Normalize turns a git remote URL into a comparable identity string, e.g.
// "github.com/org/repo". It strips credentials, scheme, and a trailing
// ".git" suffix so that https/ssh/scp-style URLs to the same repo compare
// equal.
func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty remote URL")
	}

	var host, path string

	switch {
	case strings.Contains(raw, "://"):
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse remote URL %q: %w", raw, err)
		}
		host = u.Hostname() // excludes both userinfo and port
		if port := u.Port(); port != "" && port != defaultPortFor(u.Scheme) {
			// Only a non-default port makes two URLs meaningfully
			// different hosts; otherwise ssh://host:22/x and host:x (scp
			// form) would normalize differently and a genuinely known
			// remote could be misclassified as unknown (E2).
			host = host + ":" + port
		}
		path = u.Path

	case scpLike.MatchString(raw):
		m := scpLike.FindStringSubmatch(raw)
		host = m[1]
		path = m[2]

	default:
		// Local filesystem path or unrecognized form: not a network remote,
		// nothing to normalize against a known-remote allowlist.
		return "", fmt.Errorf("not a recognized remote URL form: %q", raw)
	}

	host = strings.ToLower(host) // hostnames are case-insensitive
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimRight(path, "/") // trailing slash before stripping ".git"
	path = strings.TrimSuffix(path, ".git")
	// path is NOT lowercased: self-hosted Gitea/cgit-style hosts can be
	// case-sensitive, where org/RepoA and org/repoa are different
	// repositories — lowercasing here would let a push to one be
	// misclassified as the known-good other (E1).

	if host == "" || path == "" {
		return "", fmt.Errorf("could not extract host/path from remote URL %q", raw)
	}

	return host + "/" + path, nil
}

func defaultPortFor(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	case "git":
		return "9418"
	default:
		return ""
	}
}
