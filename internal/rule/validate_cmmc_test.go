package rule

import (
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// @spec rule-cmmc-l2-derived-refs
// @ac AC-02
//
// These refs are generated, and a generated file invites hand editing. The
// invariant is what makes "only reviewed mappings reach a customer" enforceable
// rather than a convention: an extra practice asserts a mapping nobody
// reviewed, and a missing one means the emission went stale.
func TestValidate_CMMCDerivationDrift(t *testing.T) {
	t.Run("rule-cmmc-l2-derived-refs/AC-02", func(t *testing.T) {})

	base := func(refs map[string]interface{}) *api.Rule {
		return &api.Rule{ID: "r", Title: "t", Severity: "medium", References: refs}
	}
	find := func(errs []ValidationError, want string) bool {
		for _, e := range errs {
			if strings.Contains(e.Field, "cmmc_l2") && strings.Contains(e.Msg, want) {
				return true
			}
		}
		return false
	}

	t.Run("a hand-added practice is rejected", func(t *testing.T) {
		r := base(map[string]interface{}{
			"nist_800_171": []interface{}{"3.1.8[b]"},
			"cmmc_l2":      []interface{}{"AC.L2-3.1.8", "AC.L2-3.1.99"},
		})
		if errs := Validate(r, ValidateOptions{}); !find(errs, "does not follow") {
			t.Errorf("unreviewed practice accepted; errors=%v", errs)
		}
	})

	t.Run("a stale emission is rejected", func(t *testing.T) {
		r := base(map[string]interface{}{
			"nist_800_171": []interface{}{"3.1.8[b]", "3.3.1[c]"},
			"cmmc_l2":      []interface{}{"AC.L2-3.1.8"},
		})
		if errs := Validate(r, ValidateOptions{}); !find(errs, "missing") {
			t.Errorf("stale emission accepted; errors=%v", errs)
		}
	})

	t.Run("practices without any reviewed source are rejected", func(t *testing.T) {
		r := base(map[string]interface{}{
			"cmmc_l2": []interface{}{"AC.L2-3.1.8"},
		})
		if errs := Validate(r, ValidateOptions{}); !find(errs, "no reviewed") {
			t.Errorf("practice with no 800-171 source accepted; errors=%v", errs)
		}
	})

	t.Run("the exact derivation passes", func(t *testing.T) {
		r := base(map[string]interface{}{
			"nist_800_171": []interface{}{"3.1.7[a]", "3.1.7[d]"},
			"cmmc_l2":      []interface{}{"AC.L2-3.1.7"},
		})
		for _, e := range Validate(r, ValidateOptions{}) {
			if strings.Contains(e.Field, "cmmc_l2") {
				t.Errorf("correct derivation rejected: %v", e)
			}
		}
	})

	t.Run("a rule with neither is fine", func(t *testing.T) {
		r := base(map[string]interface{}{"nist_800_53": []interface{}{"AC-6"}})
		for _, e := range Validate(r, ValidateOptions{}) {
			if strings.Contains(e.Field, "cmmc_l2") {
				t.Errorf("unmapped rule flagged: %v", e)
			}
		}
	})
}
