// contract.go is the single source of truth for CHECK-METHOD parameter
// contracts — the check-side mirror of internal/mechanism/contract.go.
//
// Every entry is derived by reading the param accesses in the corresponding
// check function in check.go (stringParam/optionalStringParam/
// stringSliceParam/boolParam + direct params[...] reads), NOT from
// CANONICAL_RULE_SCHEMA_V1.md — the schema §3.5.3 table is stale and
// contradicts the implementation (it lists methods that don't exist and omits
// real ones). The schema doc is regenerated FROM this map, not the reverse.
//
// Verified code semantics this contract encodes faithfully (do not "fix" them
// here — they are how the engine behaves today):
//   - file_permissions reads ONLY path/mode/owner/group. It does NOT read
//     glob/find_paths/find_type (those are file_permissions *remediation*
//     params). Rules whose file_permission check declares glob are silently
//     broken (the check ignores it) — they belong in the ratchet, not the
//     allowed set.
//   - service_state: enabled+active are BOTH optional and AND-combined (two
//     independent if-blocks, check.go) — NOT a OneOf/XOR.
//   - command: at-least-one of cmd/run (cmd wins if both present); systemd_target
//     at-least-one of expected/not_expected (runtime-enforced).
//   - config_value comparison is case-INSENSITIVE (strings.EqualFold);
//     sysctl_value is case-SENSITIVE exact. The comparator feature (a later PR)
//     must preserve this asymmetry for ==/!=.
//
// 'comparator' is intentionally ABSENT from config_value/sysctl_value: 19 corpus
// rules declare it but no check method reads it. A later PR adds it to Optional
// once checkConfigValue/checkSysctlValue actually honor it; until then the
// closed-world validator flags it (those rules sit in the ratchet).
package check

import "sort"

// CheckContract is the parameter contract for one check method. It mirrors
// internal/mechanism.Contract so the validator wiring is symmetric.
type CheckContract struct {
	Required []string
	Optional []string
	// OneOf groups: at least one member of each group must be present.
	OneOf [][]string
}

// CheckContracts maps each check method (api.Check.Method) to its parameter
// contract. 24 functional methods; file_permission is an alias of
// file_permissions sharing one contract.
var CheckContracts = map[string]CheckContract{
	"config_value":          {Required: []string{"path", "key", "expected"}, Optional: []string{"delimiter", "scan_pattern"}},
	"sysctl_value":          {Required: []string{"key", "expected"}},
	"package_installed":     {Required: []string{"name"}},
	"package_absent":        {Required: []string{"name"}},
	"package_state":         {Required: []string{"name"}, Optional: []string{"state"}},
	"dpkg_installed":        {Required: []string{"name"}},
	"dpkg_absent":           {Required: []string{"name"}},
	"apparmor_state":        {Optional: []string{"state"}},
	"file_exists":           {Required: []string{"path"}},
	"file_absent":           {Required: []string{"path"}},
	"file_permissions":      {Required: []string{"path"}, Optional: []string{"mode", "owner", "group"}},
	"file_permission":       {Required: []string{"path"}, Optional: []string{"mode", "owner", "group"}},
	"file_content_match":    {Required: []string{"path", "pattern"}},
	"file_content":          {Required: []string{"path", "expected_content"}},
	"service_enabled":       {Required: []string{"name"}},
	"service_active":        {Required: []string{"name"}},
	"service_state":         {Required: []string{"name"}, Optional: []string{"enabled", "active"}},
	"audit_rule_exists":     {Required: []string{"rule"}},
	"sshd_effective_config": {Required: []string{"key", "expected"}},
	"mount_option":          {Required: []string{"mount_point", "options"}},
	"kernel_module_state":   {Required: []string{"name"}, Optional: []string{"state"}},
	"grub_parameter":        {Required: []string{"key", "expected"}},
	"selinux_state":         {Required: []string{"state"}},
	"systemd_target":        {OneOf: [][]string{{"expected", "not_expected"}}},
	"command":               {OneOf: [][]string{{"cmd", "run"}}, Optional: []string{"expected_output", "expected_stdout", "expected_exit"}},
}

// KnownCheckMethod reports whether method has a registered check contract.
func KnownCheckMethod(method string) bool { _, ok := CheckContracts[method]; return ok }

// ValidateCheckParams reports contract violations for a check method given the
// parameter keys a rule provides. Empty result means the params conform. It
// mirrors mechanism.ValidateParams: closed-world (unknown params are rejected),
// required + OneOf enforced. It validates keys, not value domains.
func ValidateCheckParams(method string, keys []string) []string {
	c, ok := CheckContracts[method]
	if !ok {
		return []string{"unknown check method '" + method + "'"}
	}
	have := make(map[string]bool, len(keys))
	for _, k := range keys {
		have[k] = true
	}
	allowed := make(map[string]bool)
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
			problems = append(problems, "missing required param '"+k+"'")
		}
	}
	for _, g := range c.OneOf {
		if !anyKeyPresent(have, g) {
			problems = append(problems, "requires one of "+quoteJoin(g))
		}
	}
	var unknown []string
	for _, k := range keys {
		if !allowed[k] {
			unknown = append(unknown, "'"+k+"'")
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		problems = append(problems, "unknown param(s) "+joinComma(unknown))
	}
	sort.Strings(problems)
	return problems
}

func anyKeyPresent(have map[string]bool, group []string) bool {
	for _, k := range group {
		if have[k] {
			return true
		}
	}
	return false
}

func quoteJoin(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = "'" + s + "'"
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
