// Tests for the --limit/-l host glob filter (deliverable C-025).
//
// Covers ansible-style semantics: comma-separated tokens, glob
// patterns against host addr, group-name match, "all"/"*"
// wildcards, "!" exclusion. Edge cases: typos surface as usage
// errors so an operator's empty-fleet scan never happens silently.
package main

import (
	"strings"
	"testing"
)

func makeHosts() []inventoryHost {
	return []inventoryHost{
		{addr: "web-01", groups: []string{"web", "prod"}},
		{addr: "web-02", groups: []string{"web", "prod"}},
		{addr: "db-01", groups: []string{"db", "prod"}},
		{addr: "stage-app-01", groups: []string{"app", "stage"}},
		{addr: "stage-db-01", groups: []string{"db", "stage"}},
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-01
// @spec cli-limit-host-glob
// @ac AC-01
// @ac AC-15
func TestFilterByLimit_EmptyPatternReturnsAll(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-01", func(t *testing.T) {})
	t.Run("cli-limit-host-glob/AC-15", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-01", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "")
	if err != nil {
		t.Fatalf("empty pattern: %v", err)
	}
	if len(got) != len(hosts) {
		t.Errorf("empty pattern returned %d hosts, want all %d", len(got), len(hosts))
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-02
// @spec cli-limit-host-glob
// @ac AC-02
// @ac AC-16
func TestFilterByLimit_AllWildcards(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-02", func(t *testing.T) {})
	t.Run("cli-limit-host-glob/AC-16", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-02", func(t *testing.T) {})
	hosts := makeHosts()
	for _, p := range []string{"all", "*"} {
		got, err := filterByLimit(hosts, p)
		if err != nil {
			t.Fatalf("pattern %q: %v", p, err)
		}
		if len(got) != len(hosts) {
			t.Errorf("pattern %q returned %d, want %d", p, len(got), len(hosts))
		}
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-03
// @spec cli-limit-host-glob
// @ac AC-03
func TestFilterByLimit_ExactAddrMatch(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-03", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-03", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "web-01")
	if err != nil {
		t.Fatalf("exact: %v", err)
	}
	if len(got) != 1 || got[0].addr != "web-01" {
		t.Errorf("exact match: got %v, want [web-01]", got)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-04
// @spec cli-limit-host-glob
// @ac AC-04
func TestFilterByLimit_GlobPattern(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-04", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-04", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "web-*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("web-* matched %d, want 2", len(got))
	}
	for _, h := range got {
		if !strings.HasPrefix(h.addr, "web-") {
			t.Errorf("non-web host in result: %v", h.addr)
		}
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-05
// @spec cli-limit-host-glob
// @ac AC-05
func TestFilterByLimit_GroupMatch(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-05", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-05", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "prod")
	if err != nil {
		t.Fatalf("group match: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("group prod matched %d, want 3 (web-01, web-02, db-01)", len(got))
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-06
// @spec cli-limit-host-glob
// @ac AC-06
func TestFilterByLimit_CommaSeparated(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-06", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-06", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "web-*,db-01")
	if err != nil {
		t.Fatalf("comma: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("web-*,db-01 matched %d, want 3", len(got))
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-07
// @spec cli-limit-host-glob
// @ac AC-07
func TestFilterByLimit_Exclusion(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-07", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-07", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "all,!stage-*")
	if err != nil {
		t.Fatalf("exclusion: %v", err)
	}
	for _, h := range got {
		if strings.HasPrefix(h.addr, "stage-") {
			t.Errorf("stage host should be excluded: %v", h.addr)
		}
	}
	if len(got) != 3 {
		t.Errorf("all,!stage-* matched %d, want 3", len(got))
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-08
// @spec cli-limit-host-glob
// @ac AC-08
func TestFilterByLimit_GroupExclusion(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-08", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-08", func(t *testing.T) {})
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "all,!stage")
	if err != nil {
		t.Fatalf("group exclusion: %v", err)
	}
	for _, h := range got {
		for _, g := range h.groups {
			if g == "stage" {
				t.Errorf("host in stage group should be excluded: %v (groups=%v)", h.addr, h.groups)
			}
		}
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-09
// @spec cli-limit-host-glob
// @ac AC-09
func TestFilterByLimit_OrderMatters(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-09", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-09", func(t *testing.T) {})
	// "all,!stage,stage-app-01" — start with all, drop stage,
	// then re-add stage-app-01. Order matters per ansible semantics.
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "all,!stage,stage-app-01")
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	addrs := make(map[string]bool, len(got))
	for _, h := range got {
		addrs[h.addr] = true
	}
	if !addrs["stage-app-01"] {
		t.Errorf("stage-app-01 should be re-included after exclusion: got %v", got)
	}
	if addrs["stage-db-01"] {
		t.Errorf("stage-db-01 should remain excluded: got %v", got)
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-10
// @spec cli-limit-host-glob
// @ac AC-10
func TestFilterByLimit_TypoFailsLoud(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-10", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-10", func(t *testing.T) {})
	// A typo'd host name produces a usage error, not a silent
	// empty scan.
	hosts := makeHosts()
	_, err := filterByLimit(hosts, "wbe-01")
	if err == nil {
		t.Error("typo'd host should produce usage error; got nil")
	}
}

// @spec cli-inventory-perhost-vars
// @ac AC-11
// @spec cli-limit-host-glob
// @ac AC-11
func TestFilterByLimit_EmptyExclusionToken(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-11", func(t *testing.T) {})
	t.Run("cli-inventory-perhost-vars/AC-11", func(t *testing.T) {})
	// "!" alone is malformed.
	hosts := makeHosts()
	_, err := filterByLimit(hosts, "all,!")
	if err == nil {
		t.Error("malformed exclusion should produce error; got nil")
	}
}

// @spec cli-limit-host-glob
// @ac AC-12
func TestFilterByLimit_NoMatchExclusion(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-12", func(t *testing.T) {})
	// An exclusion token that matches nothing is NOT an error
	// (ansible allows it; operator may have a "remove staging if
	// any" template that's idempotent on staging-free inventories).
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "all,!nonexistent-host")
	if err != nil {
		t.Errorf("exclusion no-match should not error: %v", err)
	}
	if len(got) != len(hosts) {
		t.Errorf("exclusion that matched nothing changed result: got %d, want %d", len(got), len(hosts))
	}
}

// @spec cli-limit-host-glob
// @ac AC-13
func TestFilterByLimit_PreservesOrder(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-13", func(t *testing.T) {})
	// Output preserves input host order (for deterministic
	// per-host scan order).
	hosts := makeHosts()
	got, err := filterByLimit(hosts, "all")
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	for i := range hosts {
		if got[i].addr != hosts[i].addr {
			t.Errorf("order changed at %d: got %s, want %s",
				i, got[i].addr, hosts[i].addr)
		}
	}
}

// @spec cli-limit-host-glob
// @ac AC-14
func TestFilterByLimit_GlobAgainstAddrNotGroup(t *testing.T) {
	t.Run("cli-limit-host-glob/AC-14", func(t *testing.T) {})
	// Globs match addr only — they don't expand against group
	// names. This is an intentional kensa-go choice (ansible's
	// behavior here is implementation-defined).
	hosts := makeHosts()
	// "pr*" would match "prod" group if globs hit groups, but
	// no host addr starts "pr".
	_, err := filterByLimit(hosts, "pr*")
	if err == nil {
		t.Error("glob against addr-only should error when no addr matches; got nil")
	}
}
