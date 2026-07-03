package rule

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handlers/configset"
)

// @spec value-domains
// @ac AC-01
func TestSeparatorDomainMatchesHandler(t *testing.T) {
	t.Run("value-domains/AC-01", func(t *testing.T) {})
	// SSOT parity: the validator's separator domain must equal the handler's
	// accepted set exactly, so they cannot drift.
	got := mechanismValueDomains["config_set"]["separator"]
	want := configset.SeparatorValues()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("separator domain drifted from configset.SeparatorValues(): got %v want %v", got, want)
	}
}

// @spec value-domains
// @ac AC-02
func TestValidateValueDomains(t *testing.T) {
	t.Run("value-domains/AC-02", func(t *testing.T) {})

	badSep := &api.Rule{ID: "x-not-allowlisted", Implementations: []api.Implementation{{
		Remediation: api.Remediation{Mechanism: "config_set", Params: api.Params{
			"path": "/etc/login.defs", "key": "K", "value": "1", "separator": "\t",
		}},
	}}}
	if errs := ValueDomainErrors(badSep); len(errs) == 0 {
		t.Error("config_set separator '\\t' must be flagged")
	}

	goodSep := &api.Rule{ID: "y-not-allowlisted", Implementations: []api.Implementation{{
		Remediation: api.Remediation{Mechanism: "config_set", Params: api.Params{
			"path": "/etc/login.defs", "key": "K", "value": "1", "separator": " ",
		}},
	}}}
	if errs := ValueDomainErrors(goodSep); len(errs) != 0 {
		t.Errorf("config_set separator ' ' should pass; got %v", errs)
	}

	badState := &api.Rule{ID: "z-not-allowlisted", Implementations: []api.Implementation{{
		Check: api.Check{Method: "package_state", Params: api.Params{"name": "p", "state": "installed"}},
	}}}
	if errs := ValueDomainErrors(badState); len(errs) == 0 {
		t.Error("package_state state 'installed' must be flagged (not in {absent,present})")
	}

	// If any rule is still allowlisted, it must be skipped despite a bad
	// separator. (The value-domain allowlist is now empty — every corpus
	// param value conforms — so this loop is vacuous; kept robust to future
	// allowlist state. The badSep/badState assertions above already prove the
	// enforcement side.)
	for id := range KnownValueDomainViolators() {
		skipped := &api.Rule{ID: id, Implementations: []api.Implementation{{
			Remediation: api.Remediation{Mechanism: "config_set", Params: api.Params{
				"path": "/etc/login.defs", "key": "K", "value": "1", "separator": "\t\t",
			}},
		}}}
		if errs := ValueDomainErrors(skipped); len(errs) != 0 {
			t.Errorf("allowlisted rule %s must be skipped; got %v", id, errs)
		}
	}
}
