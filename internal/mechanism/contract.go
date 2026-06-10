// Package mechanism is the single source of truth for remediation-mechanism
// parameter contracts.
//
// The parameter names below are the ratified contract from
// docs/foundation_docs/CANONICAL_RULE_SCHEMA_V1.md §3.5.4. Three artifacts must
// all agree with this map:
//
//  1. the rule corpus (rules/**/*.yml) — checked by the rule validator (Layer 2,
//     internal/rule.validateRemediationParams);
//  2. the handler implementations (internal/handlers/*) — checked by the
//     corpus↔handler integration test (Layer 3, cmd/kensa);
//  3. the schema doc itself.
//
// This package has no dependencies beyond the standard library so both the
// validator and the test can import it without cycles. It is pure data plus the
// lookup helpers — the contract changes only by a deliberate, reviewed edit
// here, which is the tripwire the original param-name drift lacked.
package mechanism

import "sort"

// Contract is the parameter contract for one remediation mechanism.
type Contract struct {
	// Required params that must be present.
	Required []string
	// Optional params that may be present.
	Optional []string
	// OneOf groups: for each group, at least one member must be present.
	// Used by file_permissions (single path | find-based selection).
	OneOf [][]string
}

// Contracts maps each mechanism name to its parameter contract, using the
// schema §3.5.4 "Key Fields" names. Service/restart/reload/notify are extracted
// to dedicated api.Remediation struct fields by the parser and never appear in
// api.Params, so they are intentionally absent here.
var Contracts = map[string]Contract{
	"apt_absent":                {Required: []string{"name"}},
	"apt_present":               {Required: []string{"name"}},
	"audit_rule_set":            {Required: []string{"rule"}, Optional: []string{"persist_file"}},
	"authselect_feature_enable": {Required: []string{"feature"}},
	"command_exec":              {Required: []string{"run"}, Optional: []string{"unless"}},
	"config_append":             {Required: []string{"path", "line"}},
	"config_set":                {Required: []string{"path", "key", "value"}, Optional: []string{"separator"}},
	"config_set_dropin":         {Required: []string{"dir", "file", "key", "value"}, Optional: []string{"section", "content"}},
	"cron_job":                  {Required: []string{"schedule", "command", "user"}, Optional: []string{"name", "file"}},
	"crypto_policy_set":         {Required: []string{"policy"}},
	"crypto_policy_subpolicy":   {Required: []string{"subpolicy"}, Optional: []string{"unless"}},
	"dconf_set":                 {Required: []string{"schema", "key", "value", "file"}, Optional: []string{"lock", "db", "value_type"}},
	"file_absent":               {Required: []string{"path"}},
	"file_content":              {Required: []string{"path", "content"}, Optional: []string{"owner", "group", "mode"}},
	"file_permissions": {
		OneOf:    [][]string{{"path", "find_paths"}},
		Optional: []string{"owner", "group", "mode", "find_type", "find_args", "find_name", "glob", "unless"},
	},
	"grub_parameter_remove": {Required: []string{"key"}},
	"grub_parameter_set":    {Required: []string{"key", "value"}},
	"kernel_module_disable": {Required: []string{"name"}},
	"manual":                {Optional: []string{"note"}},
	"mount_option_set":      {Required: []string{"mount_point", "options"}},
	"package_absent":        {Required: []string{"name"}},
	"package_present":       {Required: []string{"name"}},
	"pam_module_arg":        {Required: []string{"module", "action", "arg", "files"}, Optional: []string{"type", "arg_regex"}},
	"pam_module_configure":  {Required: []string{"service", "module", "type", "control"}, Optional: []string{"args"}},
	"selinux_boolean_set":   {Required: []string{"name", "value"}, Optional: []string{"persistent"}},
	"service_disabled":      {Required: []string{"name"}, Optional: []string{"stop"}},
	"service_enabled":       {Required: []string{"name"}, Optional: []string{"start"}},
	"service_masked":        {Required: []string{"name"}, Optional: []string{"stop"}},
	"sysctl_set":            {Required: []string{"key", "value"}, Optional: []string{"persist_file"}},
}

// HandlerParamDivergence records mechanisms whose handler currently requires a
// parameter name that contradicts this contract (the schema/corpus names).
//
// Each entry is confirmed technical debt from the 2026-06-09 end-to-end test
// (docs/test_docs/E2E_LIVE_TEST_2026-06-09.md, finding F1): the handler reads a
// different key than the rules send, so every conforming rule of that mechanism
// fails at Capture. The fix is to align the handler to the contract name (with
// the proper §7 review for handler changes) and delete the entry here.
//
// The Layer-3 integration test (cmd/kensa) treats these as expected failures so
// CI stays green, and ratchets: it fails if a listed mechanism no longer
// diverges (entry is stale, remove it) or if a NON-listed mechanism starts
// diverging (a regression).
var HandlerParamDivergence = map[string]string{
	// config_set: ALIGNED to the contract — handler reads "path"
	// (fix/handler-param-config-set). Entry removed; the ~92 config_set rules
	// now decode and remediate.
	"config_set_dropin":     `handler reads "path"; contract/corpus use "dir"+"file"`,
	"kernel_module_disable": `handler reads "module"; contract/corpus use "name"`,
	"mount_option_set":      `handler reads "option"; contract/corpus use "options"`,
	"audit_rule_set":        `handler reads "rule_file"; contract/corpus use "rule"`,
	"pam_module_configure":  `handler reads "module_type"; contract/corpus use "type"`,
	"cron_job":              `handler requires "name", which the contract does not define`,
}

// Known returns whether mech has a registered contract.
func Known(mech string) bool { _, ok := Contracts[mech]; return ok }

// ValidateParams reports contract violations for a mechanism given the set of
// parameter keys a rule provides. It returns a sorted, deterministic list of
// human-readable problems; an empty result means the params conform.
//
// It does not know whether the handler honors the contract — that is Layer 3's
// job. ValidateParams answers only "does this rule follow the schema?".
func ValidateParams(mech string, keys []string) []string {
	c, ok := Contracts[mech]
	if !ok {
		return []string{"unknown mechanism " + quote(mech)}
	}
	have := make(map[string]bool, len(keys))
	for _, k := range keys {
		have[k] = true
	}
	allowed := make(map[string]bool)
	// universalOptional params are cross-mechanism guards/modifiers handled
	// outside any single handler's param decode (e.g. "unless" gates the step).
	allowed["unless"] = true
	for _, k := range c.Required {
		allowed[k] = true
	}
	for _, k := range c.Optional {
		allowed[k] = true
	}
	for _, g := range c.OneOf {
		for _, k := range g {
			allowed[k] = true
		}
	}

	var problems []string
	for _, k := range c.Required {
		if !have[k] {
			problems = append(problems, "missing required param "+quote(k))
		}
	}
	for _, g := range c.OneOf {
		if !anyPresent(have, g) {
			problems = append(problems, "requires one of "+quoteList(g))
		}
	}
	var unknown []string
	for _, k := range keys {
		if !allowed[k] {
			unknown = append(unknown, quote(k))
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		problems = append(problems, "unknown param(s) "+joinComma(unknown))
	}
	sort.Strings(problems)
	return problems
}

func anyPresent(have map[string]bool, group []string) bool {
	for _, k := range group {
		if have[k] {
			return true
		}
	}
	return false
}

func quote(s string) string { return "'" + s + "'" }

func quoteList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = quote(s)
	}
	return joinComma(q)
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
