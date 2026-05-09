package main

import (
	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/varsub"
)

// ruleLoadFilterSpec captures the rule-load + filter inputs as a
// single value so they can be passed to inventory-mode goroutines.
// Phase 3.7 introduced this so each per-host goroutine can re-run
// the load+filter pipeline against that host's full 5-tier
// variable resolution, not the corpus-wide globalVars.
//
// The struct intentionally does NOT carry varsub.Variables — that
// is a per-host runtime parameter, supplied to LoadAndFilter.
type ruleLoadFilterSpec struct {
	rulesDir   string
	rulePaths  []string // --rule values + positional *.yml args, pre-concatenated

	// Filter inputs, all already validated against the global
	// corpus pass (so we don't re-validate per host; the
	// vocabulary doesn't change with substitution).
	severities         []string // post-validateSeverities
	tags               []string // post-normalizeTags
	category           string
	framework          string // canonical, post-validateFramework
	controlFilters     []controlFilter
}

// LoadAndFilter loads the corpus with vars and applies the
// severity / tag / category / framework / control filter chain.
// Returns the filtered rule slice. Empty-after-filter is NOT a
// usage error here — the caller decides how to react. The
// global validation pass (in runCheck/runRemediate) catches
// vocabulary errors and fully-empty-after-filter cases up front;
// per-host empty-after-filter (when host vars filter rules
// further) is a recoverable per-host condition.
func (s ruleLoadFilterSpec) LoadAndFilter(vars varsub.Variables) ([]*api.Rule, error) {
	rules, err := loadRulesFromDirOrFiles(s.rulesDir, s.rulePaths, vars)
	if err != nil {
		return nil, err
	}
	rules = filterRulesBySeverity(rules, s.severities)
	rules = filterRulesByTag(rules, s.tags)
	rules = filterRulesByCategory(rules, s.category)
	rules = filterRulesByFramework(rules, s.framework)
	rules = filterRulesByControl(rules, s.controlFilters)
	return rules, nil
}
