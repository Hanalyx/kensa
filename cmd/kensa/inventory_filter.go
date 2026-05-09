package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// filterByLimit applies an ansible-style --limit pattern to an
// inventory host list. Returns the subset of hosts matching the
// pattern.
//
// Pattern syntax (matches ansible's --limit / --hosts semantics):
//
//   - Comma-separated patterns are OR'd together: "web-*,db-01"
//     matches every host with addr starting "web-" plus the host
//     "db-01".
//   - Patterns prefixed with `!` exclude matches: "all,!staging-*"
//     starts with all hosts and removes those starting "staging-".
//     The exclusion always loses against later includes; include
//     order matters.
//   - "all" or "*" matches every host.
//   - Bare alphanumeric tokens match either the host addr exactly
//     (case-sensitive) OR a group name (any host whose groups
//     slice contains the token). Group match takes precedence —
//     ansible's behavior is "if it looks like a group, treat it
//     as a group".
//   - Tokens containing `*` or `?` are filepath-style globs against
//     the host addr only (NOT against group names — globs against
//     groups would require a separate syntax that ansible doesn't
//     define).
//
// An empty pattern returns every host (the operator didn't pass
// --limit). A pattern that matches nothing returns an empty slice
// without erroring; the caller decides whether to surface "no
// hosts matched" as a usage error or as a successful no-op.
func filterByLimit(hosts []inventoryHost, pattern string) ([]inventoryHost, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return hosts, nil
	}

	tokens := splitLimitTokens(pattern)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("--limit %q parsed to zero tokens", pattern)
	}

	// included tracks which hosts are currently selected.
	// Process tokens left-to-right: include tokens add hosts;
	// exclude tokens (! prefix) remove hosts. Order matters
	// per ansible semantics.
	included := make([]bool, len(hosts))

	for _, tok := range tokens {
		exclude := false
		t := tok
		if strings.HasPrefix(t, "!") {
			exclude = true
			t = strings.TrimPrefix(t, "!")
		}
		if t == "" {
			return nil, fmt.Errorf("--limit %q: empty token after %q prefix", pattern, "!")
		}
		matchedAny := false
		for i, h := range hosts {
			if matchesLimitToken(h, t) {
				matchedAny = true
				included[i] = !exclude
			}
		}
		if !exclude && !matchedAny {
			// Include token that matched nothing; surface as
			// usage error so an operator with a typo doesn't
			// silently get an empty fleet scan.
			return nil, fmt.Errorf("--limit %q: no host or group matched", t)
		}
	}

	out := make([]inventoryHost, 0, len(hosts))
	for i, want := range included {
		if want {
			out = append(out, hosts[i])
		}
	}
	return out, nil
}

// splitLimitTokens splits a limit pattern on commas, trimming
// whitespace around each token. Tokens are NOT shell-quoted; ansible
// treats commas as bare separators.
func splitLimitTokens(pattern string) []string {
	parts := strings.Split(pattern, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// matchesLimitToken reports whether host matches the given limit
// token. Group-name match takes precedence over addr-match per
// ansible behavior.
func matchesLimitToken(host inventoryHost, token string) bool {
	if token == "all" || token == "*" {
		return true
	}
	// Group match: ansible treats bare alphanumeric tokens as
	// group names if they match. We extend slightly: any token
	// without a glob meta-character can match a group name
	// (groups can't contain `*` or `?` per the inventory parser).
	if !strings.ContainsAny(token, "*?") {
		for _, g := range host.groups {
			if g == token {
				return true
			}
		}
		// Fall through to addr exact-match.
		return host.addr == token
	}
	// Glob match against addr only. filepath.Match returns an
	// error only when the pattern is malformed (e.g., unbalanced
	// brackets); treat that as a non-match rather than propagate.
	ok, err := filepath.Match(token, host.addr)
	if err != nil {
		return false
	}
	return ok
}
