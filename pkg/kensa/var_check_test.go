package kensa

import (
	"os"
	"strings"
	"testing"
)

// TestLoadersCheckVarValues covers the library half of the variable type
// check. The CLI refused a bad --var, but LoadRules accepted the same value
// with a nil error and a full corpus, so a library caller scanned with it.
// The three refused values are the ones that were measured getting through.
//
// @spec rule-public-loader
func TestLoadersCheckVarValues(t *testing.T) {
	t.Run("rule-public-loader/AC-13", func(t *testing.T) {
		// @spec rule-public-loader
		// @ac AC-13
		dir := corpusDir(t)
		fsys := os.DirFS(dir)

		refused := []struct{ name, value string }{
			{"pam_faillock_deny", "three"},
			{"pam_faillock_deny", "3.5"},
			{"authorized_listening_ports", "22, 443"},
		}
		for _, c := range refused {
			vars := map[string]string{c.name: c.value}
			if err := CheckVarValue(c.name, c.value); err == nil {
				t.Errorf("CheckVarValue(%q, %q) accepted a value that does not fit the type", c.name, c.value)
			}
			rules, err := LoadRules(dir, nil, vars)
			if err == nil || len(rules) != 0 {
				t.Errorf("LoadRules with %s=%q: got %d rules and err %v, want no rules and an error", c.name, c.value, len(rules), err)
			} else if !strings.Contains(err.Error(), c.name) {
				t.Errorf("LoadRules error does not name %s: %v", c.name, err)
			}
			rules, err = LoadRulesFS(fsys, vars)
			if err == nil || len(rules) != 0 {
				t.Errorf("LoadRulesFS with %s=%q: got %d rules and err %v, want no rules and an error", c.name, c.value, len(rules), err)
			} else if !strings.Contains(err.Error(), c.name) {
				t.Errorf("LoadRulesFS error does not name %s: %v", c.name, err)
			}
		}

		accepted := []struct{ name, value string }{
			{"pam_faillock_deny", "5"},
			{"pam_faillock_deny", ""},
			{"authorized_listening_ports", "22,443"},
			{"site_variable_kensa_does_not_ship", "anything at all"},
		}
		for _, c := range accepted {
			if err := CheckVarValue(c.name, c.value); err != nil {
				t.Errorf("CheckVarValue(%q, %q) refused a valid value: %v", c.name, c.value, err)
			}
		}
		// One load with every accepted value at once is enough to show the
		// loaders do not refuse them.
		vars := map[string]string{
			"pam_faillock_deny":                 "5",
			"authorized_listening_ports":        "22,443",
			"site_variable_kensa_does_not_ship": "anything at all",
		}
		if rules, err := LoadRules(dir, nil, vars); err != nil || len(rules) == 0 {
			t.Errorf("LoadRules refused valid values: %d rules, err %v", len(rules), err)
		}
		if rules, err := LoadRulesFS(fsys, map[string]string{"pam_faillock_deny": ""}); err != nil || len(rules) == 0 {
			t.Errorf("LoadRulesFS refused an empty value: %d rules, err %v", len(rules), err)
		}
	})
}
