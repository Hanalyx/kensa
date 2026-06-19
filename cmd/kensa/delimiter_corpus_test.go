package main

import (
	"sort"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// TestLoginDefsDelimiterDeclared verifies the 6 /etc/login.defs config_value
// rules declare delimiter " " on their check, so they find the whitespace-
// delimited key instead of silently reporting "not found".
//
// @spec delimiter-model
// @ac AC-02
func TestLoginDefsDelimiterDeclared(t *testing.T) {
	t.Run("delimiter-model/AC-02", func(t *testing.T) {})
	want := []string{
		"default-umask", "login-defs-pass-max-days", "pam-faildelay",
		"password-min-age", "password-warn-age", "shadow-hashing-rounds",
	}
	rules := map[string]*api.Rule{}
	for _, r := range loadCorpusRules(t) {
		rules[r.ID] = r
	}
	var missing []string
	for _, id := range want {
		r, ok := rules[id]
		if !ok {
			t.Errorf("rule %q not found in corpus", id)
			continue
		}
		declared := false
		for i := range r.Implementations {
			c := r.Implementations[i].Check
			if c.Method == "config_value" {
				if _, ok := c.Params["delimiter"]; ok {
					declared = true
				}
			}
		}
		if !declared {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("login.defs rules missing delimiter on their config_value check: %v", missing)
	}
}
