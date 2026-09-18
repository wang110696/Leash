package gitremote

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"https", "https://github.com/org/repo.git", "github.com/org/repo", false},
		{"https no dotgit", "https://github.com/org/repo", "github.com/org/repo", false},
		{"https with credentials", "https://tok3n@github.com/org/repo.git", "github.com/org/repo", false},
		{"scp-like", "git@github.com:org/repo.git", "github.com/org/repo", false},
		{"scp-like no user", "github.com:org/repo.git", "github.com/org/repo", false},
		{"ssh url", "ssh://git@github.com/org/repo.git", "github.com/org/repo", false},

		// E1: host is case-folded but path is not — a case-sensitive
		// self-hosted git server (Gitea/cgit-style) can have org/RepoA and
		// org/repoa as two different repositories; lowercasing the path
		// would let a push to one be misclassified as the known-good other.
		{"host case-insensitive", "https://GitHub.com/org/repo.git", "github.com/org/repo", false},
		{"path case preserved", "https://github.com/Org/RepoA.git", "github.com/Org/RepoA", false},
		{"path case distinguishes repos", "https://github.com/org/repoa.git", "github.com/org/repoa", false},

		// E2: default port for the scheme doesn't change the identity;
		// a non-default port does. Without this, ssh://host:22/x and the
		// scp-form host:x would normalize to different identities even
		// though they're the same remote.
		{"default ssh port omitted", "ssh://git@github.com:22/org/repo.git", "github.com/org/repo", false},
		{"default https port omitted", "https://github.com:443/org/repo.git", "github.com/org/repo", false},
		{"non-default port kept", "ssh://git@example.com:2222/org/repo.git", "example.com:2222/org/repo", false},

		// trailing slash before ".git" stripping
		{"trailing slash", "https://github.com/org/repo.git/", "github.com/org/repo", false},
		{"trailing slash no dotgit", "https://github.com/org/repo/", "github.com/org/repo", false},

		{"empty", "", "", true},
		{"local path", "/Users/x/repo", "", true},
		{"malformed", "not a url at all with spaces", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Normalize(%q) = %q, nil; want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeEquivalentForms checks that https/ssh/scp forms of the same
// remote all normalize identically — the whole point of the baseline
// comparison in the git shim.
func TestNormalizeEquivalentForms(t *testing.T) {
	forms := []string{
		"https://github.com/org/repo.git",
		"https://github.com/org/repo",
		"ssh://git@github.com/org/repo.git",
		"ssh://git@github.com:22/org/repo.git",
		"git@github.com:org/repo.git",
	}

	var want string
	for i, f := range forms {
		got, err := Normalize(f)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", f, err)
		}
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q; want %q (to match %q)", f, got, want, forms[0])
		}
	}
}
