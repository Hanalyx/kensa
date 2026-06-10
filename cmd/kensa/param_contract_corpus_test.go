package main

import (
	"context"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/mechanism"
	"github.com/Hanalyx/kensa/internal/rule"
)

// This file lives in package main so every handler registered via the blank
// imports in main.go is present in handler.Default(). It is the Layer-3
// corpus↔handler integration test: it feeds every real corpus rule's
// remediation params to its real handler and asserts the handler does not
// reject them with a "missing required" parameter error — the failure mode that
// unit/fuzz tests miss because they construct synthetic params.

func corpusRulesDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "rules")
}

func loadCorpusRules(t *testing.T) []*api.Rule {
	t.Helper()
	dir := corpusRulesDir(t)
	var rules []*api.Rule
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".yml" {
			return nil
		}
		r, perr := rule.ParseFile(path)
		if perr == nil {
			rules = append(rules, r)
		}
		return nil
	})
	if err != nil {
		t.Skipf("corpus not available: %v", err)
	}
	if len(rules) == 0 {
		t.Skip("no rules found")
	}
	return rules
}

// decodeParamError runs the param-decoding entry point of a handler against a
// fake transport and returns true if it failed specifically because a required
// parameter was missing. Non-param errors (a fake transport produces empty
// command output, which some Capture parsers reject) are ignored — this test
// asserts only about the parameter contract.
func decodeParamError(h api.Handler, params api.Params) bool {
	ctx := context.Background()
	ft := engine.NewFakeTransport()
	var err error
	if ch, ok := h.(api.CaptureHandler); ok {
		_, err = ch.Capture(ctx, ft, params)
	} else {
		_, err = h.Apply(ctx, ft, params, nil)
	}
	return err != nil && strings.Contains(err.Error(), "missing required")
}

// @spec rule-param-contract
// @ac AC-06
// knownHandlerRuleGaps are rules whose params satisfy the mechanism contract
// (so Layer 2 passes them) but that the handler still rejects for a reason
// OTHER than a param-name divergence — a separate handler-capability gap to fix
// on its own. They cannot go in rule.knownNonConformingRules (that allowlist's
// ratchet requires a param-contract violation, which these do not have).
// Documented debt; this list should shrink to empty.
var knownHandlerRuleGaps = map[string]string{
	// config_set requires a non-empty value and a recognized separator; these
	// rules set a valueless flag (value:"" separator:""), e.g. `audit` and
	// `enforce_for_root`. Needs config_set valueless-flag support (or a
	// different mechanism); tracked separately from the path-name alignment.
	"pam-faillock-audit":     `config_set valueless flag (empty value/separator)`,
	"pwquality-root-enforce": `config_set valueless flag (empty value/separator)`,
}

func TestCorpusParamsDecodeThroughHandlers(t *testing.T) {
	t.Run("rule-param-contract/AC-06", func(t *testing.T) {})
	rules := loadCorpusRules(t)
	allowlist := rule.KnownNonConforming()
	divergence := mechanism.HandlerParamDivergence
	sawDivergence := make(map[string]bool)

	for _, r := range rules {
		for i := range r.Implementations {
			rem := &r.Implementations[i].Remediation
			mech := rem.Mechanism
			if mech == "" {
				continue
			}
			h, ok := handler.Default().Get(mech)
			if !ok {
				t.Errorf("%s: no registered handler for mechanism %q", r.ID, mech)
				continue
			}
			if !decodeParamError(h, rem.Params) {
				continue
			}
			// The handler rejected the rule's params. Is that an expected,
			// documented divergence — or a regression?
			_, allow := allowlist[r.ID]
			_, gap := knownHandlerRuleGaps[r.ID]
			reason, diverges := divergence[mech]
			// file_permissions handler supports only single 'path'; find-based
			// rules legitimately lack 'path' and are a known handler gap (F1).
			fpFind := mech == "file_permissions" && rem.Params["path"] == nil
			switch {
			case allow:
				// documented corpus debt; tolerated.
			case diverges:
				sawDivergence[mech] = true // documented handler debt (F1)
			case gap:
				// documented non-param handler-capability gap; tolerated.
			case fpFind:
				// documented handler feature gap.
			default:
				t.Errorf("%s [%s]: handler rejects schema-conforming params "+
					"(missing-required). This is a NEW divergence — align the handler "+
					"to internal/mechanism, or document it.", r.ID, mech)
			}
			_ = reason
		}
	}

	// Ratchet: every mechanism in the divergence ledger must still actually
	// diverge. When a handler is aligned to the contract it stops rejecting
	// rules; this then fails and forces removal of the stale ledger entry.
	for mech, reason := range divergence {
		if !sawDivergence[mech] {
			t.Errorf("HandlerParamDivergence[%q] (%s) produced no rejection — "+
				"the handler now conforms (or the corpus has no such rule). "+
				"Remove the entry from internal/mechanism.", mech, reason)
		}
	}
}
