package output

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Hanalyx/kensa-go/api"
)

// Operator-UX text rendering for scan results (C-022 — CLI Phase 2.5).
//
// Replaces the C-012 tabular rendering with a grouped/severity-aware
// layout that surfaces failures first, summarizes passes via glob
// patterns, and synthesizes operator-readable fix guidance from the
// rule's first implementation.
//
// Status mapping (display-only category — the engine's transaction
// status enum is unchanged):
//
//	StatusCommitted        → PASS (✓)
//	StatusErrored          → WARN (!) — the check itself failed
//	                          to run cleanly; advisory, not a
//	                          finding
//	StatusRolledBack       → FAIL (✗) — the rule's expected state
//	StatusPartiallyApplied   was not met
//	(any other)            → FAIL (✗)
//
// Severity badges come from rule.Severity (canonical values per
// CANONICAL_RULE_SCHEMA_V0.md §3.3: critical / high / medium / low).
// Rendered as 4-char fixed-width tokens (HIGH, MED, LOW) so columns
// align without wrapping.

// ScanRenderOptions carries the per-call rendering knobs that the
// ScanResultWriter interface doesn't model. cmd/kensa populates this
// from --verbose / detected OS info / etc., then calls
// RenderScanResult directly to bypass the writer registry for the
// configured render. The textScanWriter.WriteScanResult method
// continues to delegate with default (zero-value) options for the
// fan-out / writer-registry path.
type ScanRenderOptions struct {
	// Verbose expands the compacted PASSED list to one rule ID per
	// line instead of glob-pattern compaction. Wired by --verbose
	// (-v) on body-emitting subcommands.
	Verbose bool

	// OSLabel is the operator-facing OS label rendered in the host
	// banner (e.g., "RHEL 9.6", "Ubuntu 22.04"). Empty when the
	// caller couldn't detect the OS; the banner falls back to
	// hostID-only.
	OSLabel string
}

// RenderScanResult renders a scan result with caller-supplied
// options. cmd/kensa uses this entry point when --verbose or OS
// detection wants to influence the output. The
// ScanResultWriter-interface path continues through
// textScanWriter.WriteScanResult, which calls this function with
// default options.
func RenderScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult, opts ScanRenderOptions) error {
	return renderScanResult(w, hostID, rules, result, opts)
}

// renderScanResult is the body of textScanWriter.WriteScanResult,
// extracted into a free function so internal helpers stay package-
// private without polluting the writer's exported method body.
func renderScanResult(w io.Writer, hostID string, rules []*api.Rule, result *api.ScanResult, opts ScanRenderOptions) error {
	groups := classifyTransactions(rules, result)

	// Pre-resolve the host banner and summary so any error short-
	// circuits before partial output.
	if err := writeHostBanner(w, hostID, opts.OSLabel); err != nil {
		return err
	}
	if err := writeFailedSection(w, rules, result, groups.failed); err != nil {
		return err
	}
	if err := writeWarnSection(w, rules, result, groups.warn); err != nil {
		return err
	}
	if err := writePassedSection(w, rules, groups.passed, opts.Verbose); err != nil {
		return err
	}
	return writeSummary(w, groups)
}

// transactionGroups partitions a scan's transactions by display
// category. Indices reference into result.Transactions and rules
// (which are aligned post-Resolve in C-021).
type transactionGroups struct {
	passed []int // committed
	warn   []int // errored
	failed []int // anything else
}

func classifyTransactions(_ []*api.Rule, result *api.ScanResult) transactionGroups {
	var g transactionGroups
	for i, txr := range result.Transactions {
		switch txr.Status {
		case api.StatusCommitted:
			g.passed = append(g.passed, i)
		case api.StatusErrored:
			g.warn = append(g.warn, i)
		default:
			g.failed = append(g.failed, i)
		}
	}
	return g
}

// writeHostBanner emits the host-identification line. C-023 added
// the optional OS-label segment ("· RHEL 9.6"); C-024+ may add
// auth method or other metadata.
//
// All width math is rune-counted, not byte-counted: "─" is a
// 3-byte UTF-8 codepoint, and hostnames may contain non-ASCII
// characters (IDN labels per RFC 5890). Using len() on either
// would produce a too-short banner.
//
// osLabel is empty when the caller couldn't detect the OS; the
// banner renders just the hostID in that case.
func writeHostBanner(w io.Writer, hostID, osLabel string) error {
	const totalRunes = 60
	const prefixRunes = 4 // "─── "
	const sepRunes = 1    // " "
	hostRunes := utf8.RuneCountInString(hostID)
	osSegment := ""
	osRunes := 0
	if osLabel != "" {
		osSegment = " · " + osLabel
		osRunes = utf8.RuneCountInString(osSegment)
	}
	tailRunes := totalRunes - prefixRunes - hostRunes - osRunes - sepRunes
	if tailRunes < 4 {
		tailRunes = 4
	}
	prefix := strings.Repeat("─", prefixRunes-1) + " "
	tail := strings.Repeat("─", tailRunes)
	if _, err := fmt.Fprintf(w, "%s%s%s%s%s\n", prefix, hostID, osSegment, " ", tail); err != nil {
		return err
	}
	return nil
}

// writeFailedSection emits the FAILED group with severity, short
// reason, and synthesized fix guidance. Skipped when there are no
// failures.
func writeFailedSection(w io.Writer, rules []*api.Rule, result *api.ScanResult, indices []int) error {
	if len(indices) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "FAILED   (%3d)\n", len(indices)); err != nil {
		return err
	}
	for _, i := range indices {
		ruleID, severity, detail, fix := ruleDisplay(rules, result, i)
		if _, err := fmt.Fprintf(w, "  ✗ %-32s %-4s %s\n", truncate(ruleID, 32), severity, detail); err != nil {
			return err
		}
		if fix != "" {
			if _, err := fmt.Fprintf(w, "    └ fix: %s\n", fix); err != nil {
				return err
			}
		}
	}
	return blankLine(w)
}

// writeWarnSection emits the WARN group (errored checks). Skipped
// when there are no warnings.
func writeWarnSection(w io.Writer, rules []*api.Rule, result *api.ScanResult, indices []int) error {
	if len(indices) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "WARN     (%3d)\n", len(indices)); err != nil {
		return err
	}
	for _, i := range indices {
		ruleID, _, detail, _ := ruleDisplay(rules, result, i)
		if _, err := fmt.Fprintf(w, "  ! %-40s %s\n", truncate(ruleID, 40), detail); err != nil {
			return err
		}
	}
	return blankLine(w)
}

// passedInlineThreshold is the cutoff below which PASSED rule IDs
// render inline (one space-separated line) instead of glob-
// compacted. 8 fits an 80-column terminal at typical rule-ID
// lengths; 9+ overflows.
const passedInlineThreshold = 8

// writePassedSection emits the PASSED group. Three modes:
//
//	verbose=true     → one rule ID per line (operator opted in via -v)
//	≤ 8 passes        → inline space-separated list
//	> 8 passes        → glob-compacted via deepest-common-prefix
//	                     plus a "run with -v to expand" hint
func writePassedSection(w io.Writer, rules []*api.Rule, indices []int, verbose bool) error {
	if len(indices) == 0 {
		return nil
	}
	ids := make([]string, len(indices))
	for j, i := range indices {
		if i < len(rules) {
			ids[j] = rules[i].ID
		}
	}
	sort.Strings(ids)

	if _, err := fmt.Fprintf(w, "PASSED   (%3d)", len(indices)); err != nil {
		return err
	}

	switch {
	case verbose:
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := fmt.Fprintf(w, "  ✓ %s\n", id); err != nil {
				return err
			}
		}
	case len(ids) <= passedInlineThreshold:
		if _, err := fmt.Fprintf(w, "  ·  %s\n", strings.Join(ids, " ")); err != nil {
			return err
		}
	default:
		compact := compactPasses(ids)
		if _, err := fmt.Fprintf(w, "  ·  %s\n", compact); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "                run with -v to expand"); err != nil {
			return err
		}
	}
	return blankLine(w)
}

// writeSummary emits the progress bar and the final summary line.
func writeSummary(w io.Writer, g transactionGroups) error {
	if _, err := fmt.Fprintln(w, strings.Repeat("─", 60)); err != nil {
		return err
	}
	bar := progressBar(len(g.passed), len(g.warn), len(g.failed), 60)
	if _, err := fmt.Fprintln(w, bar); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%d passed  ·  %d failed  ·  %d warnings\n",
		len(g.passed), len(g.failed), len(g.warn))
	return err
}

// ruleDisplay extracts the per-row data points: rule ID, severity
// badge, short detail, and fix-line guidance. Returns empty strings
// where data is missing rather than erroring — operators see the
// row regardless.
func ruleDisplay(rules []*api.Rule, result *api.ScanResult, i int) (ruleID, severity, detail, fix string) {
	if i < len(rules) && rules[i] != nil {
		ruleID = rules[i].ID
		severity = severityBadge(rules[i].Severity)
		fix = synthesizeFix(rules[i])
	}
	if i < len(result.Transactions) {
		detail = humanizeDetail(result.Transactions[i])
	}
	return
}

// severityBadge converts a canonical-schema severity string to a
// 4-char fixed-width badge. Empty severity renders as 4 spaces so
// the layout doesn't shift.
func severityBadge(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "CRIT"
	case "high":
		return "HIGH"
	case "medium":
		return "MED "
	case "low":
		return "LOW "
	}
	return "    "
}

// commandExitPattern matches the canonical failure detail emitted
// by check.go's command method: a script body in quotes followed by
// "exited with code N (expected M)". Captures the actual signal
// (the exit codes) so we can render it without the script body.
var commandExitPattern = regexp.MustCompile(
	`exited with code\s+(\d+)\s*\(expected\s+(\d+)\)`)

// humanizeDetail extracts an operator-readable failure reason from
// the transaction's Steps[0].Detail or Error. Three transformations
// in priority order:
//
//  1. Multi-line script bodies (the rule's `check.command:` body
//     leaked verbatim): replace with a "(see -o json: for command
//     output)" pointer. The script body is useless at 50-char
//     truncation and the operator wanting it should use the
//     structured output.
//  2. "exited with code N (expected M)" patterns: extract just the
//     "got N, want M" signal so the actionable bit isn't past the
//     truncation cliff.
//  3. Mechanism-prefix stripping (command:, config_value:, etc.)
//     for the simpler cases.
func humanizeDetail(txr api.TransactionResult) string {
	raw := ""
	if txr.Error != nil {
		raw = txr.Error.Error()
	} else if len(txr.Steps) > 0 {
		raw = txr.Steps[0].Detail
	}
	raw = strings.TrimSpace(raw)

	// Multi-line script body heuristic: shell-script bodies leaked
	// from rules using `check.method: command` with multi-line `run:`
	// blocks. They start with '#' (a shebang or comment) and contain
	// newlines, OR they're long enough that even after truncation the
	// operator sees only the script body, never the failure reason.
	if strings.Contains(raw, "\n") || (len(raw) > 200 && (strings.HasPrefix(raw, "command: \"#") || strings.HasPrefix(raw, "command: \""))) {
		// Try to extract the exit-code signal first; that's the
		// most actionable bit when the raw detail is dominated by
		// the script body.
		if m := commandExitPattern.FindStringSubmatch(raw); len(m) == 3 {
			return fmt.Sprintf("unexpected exit (got %s, want %s)", m[1], m[2])
		}
		return "(check failed — see -o json: for command output)"
	}

	// Drop the per-mechanism prefix and any leading colon-space.
	for _, prefix := range []string{
		"command:", "config_value:", "file_exists:", "file_permissions:",
		"package_installed:", "service_enabled:", "service_active:",
		"sysctl_value:", "audit_rule_exists:", "kernel_module_loaded:",
		"selinux_boolean:", "mount_option:", "validate:",
	} {
		if strings.HasPrefix(raw, prefix) {
			raw = strings.TrimSpace(strings.TrimPrefix(raw, prefix))
			break
		}
	}

	// Try the exit-code pattern even on prefix-stripped text — the
	// pattern often follows the prefix.
	if m := commandExitPattern.FindStringSubmatch(raw); len(m) == 3 {
		return fmt.Sprintf("unexpected exit (got %s, want %s)", m[1], m[2])
	}

	// Multi-detail strings are often concatenated by "; "; show the
	// first segment only — operators reading the full detail use
	// -o json:report.json.
	if idx := strings.Index(raw, ";"); idx > 0 {
		raw = raw[:idx]
	}
	return truncate(raw, 50)
}

// synthesizeFix derives an operator-runnable shell-style fix line
// from the rule's first implementation's Remediation. Returns the
// empty string for handlers without a synthesizer (operators using
// -o json:report.json get the full detail).
//
// Supported handlers (~5 most common; other handlers fall through
// to empty):
//   - file_permissions{path, mode, [owner, group]}
//   - file_absent{path}
//   - package_present{name}
//   - package_absent{name}
//   - service_enabled{unit}
//   - service_disabled{unit}
//   - service_masked{unit}
//   - config_set{path, key, value}
//   - sysctl_set{key, value}
func synthesizeFix(r *api.Rule) string {
	if r == nil || len(r.Implementations) == 0 {
		return ""
	}
	rem := r.Implementations[0].Remediation
	if rem.Mechanism == "" {
		// Multi-step: emit nothing rather than describe step 1
		// only. An operator running a synthesized one-liner from a
		// 3-step remediation gets a partial fix and may not realize
		// the other 2 steps were silently dropped. The structured
		// output (`-o json:`) carries the full multi-step plan;
		// surfacing only step 1 here would be operator-hostile.
		return ""
	}
	return synthesizeStep(rem.Mechanism, rem.Params)
}

// synthesizeStep is the single-step synthesizer reused by
// synthesizeFix for both flat and multi-step Remediations.
func synthesizeStep(mechanism string, params api.Params) string {
	get := func(key string) string {
		v, ok := params[key]
		if !ok {
			return ""
		}
		switch x := v.(type) {
		case string:
			return x
		case int:
			return fmt.Sprintf("%d", x)
		case bool:
			return fmt.Sprintf("%t", x)
		default:
			return fmt.Sprintf("%v", x)
		}
	}
	switch mechanism {
	case "file_permissions":
		path, mode := get("path"), get("mode")
		owner, group := get("owner"), get("group")
		switch {
		case path == "":
			return ""
		case owner != "" && group != "":
			return fmt.Sprintf("chmod %s %s && chown %s:%s %s", mode, path, owner, group, path)
		case mode != "":
			return fmt.Sprintf("chmod %s %s", mode, path)
		}
		return fmt.Sprintf("review file %s", path)
	case "file_absent":
		if path := get("path"); path != "" {
			return fmt.Sprintf("rm -f %s", path)
		}
	case "package_present", "apt_present", "dnf_present":
		if name := get("name"); name != "" {
			return fmt.Sprintf("install package %s", name)
		}
	case "package_absent", "apt_absent", "dnf_absent":
		if name := get("name"); name != "" {
			return fmt.Sprintf("remove package %s", name)
		}
	case "service_enabled":
		if unit := get("unit"); unit != "" {
			return fmt.Sprintf("systemctl enable %s", unit)
		}
	case "service_disabled":
		if unit := get("unit"); unit != "" {
			return fmt.Sprintf("systemctl disable %s", unit)
		}
	case "service_masked":
		if unit := get("unit"); unit != "" {
			return fmt.Sprintf("systemctl mask %s", unit)
		}
	case "config_set", "config_set_dropin":
		path, key, value := get("path"), get("key"), get("value")
		if path != "" && key != "" {
			return fmt.Sprintf("set %s = %s in %s", key, value, path)
		}
	case "sysctl_set":
		key, value := get("key"), get("value")
		if key != "" {
			return fmt.Sprintf("sysctl -w %s=%s", key, value)
		}
	}
	return ""
}

// compactPasses takes a sorted slice of rule IDs and produces a
// glob-pattern summary like "accounts-* pam-faillock-* aslr-enabled
// audit-cmd-*".
//
// Algorithm: greedy deepest-common-prefix grouping. For the run of
// consecutive IDs sharing some prefix, the longest prefix shared by
// all members of the run wins. So "pam-faillock-deny",
// "pam-faillock-silent", "pam-faillock-unlock-time" collapse to
// "pam-faillock-*", not "pam-*" (which would lose the faillock
// specificity).
//
// Lone IDs (no neighbor in the run) render verbatim. Below 2
// members the algorithm doesn't compact at all — operators want to
// see lone outliers explicitly, not collapsed.
func compactPasses(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	var parts []string
	i := 0
	for i < len(ids) {
		// Find the longest run sharing a non-empty first-token.
		firstTok := firstDashSegment(ids[i])
		if firstTok == "" {
			parts = append(parts, ids[i])
			i++
			continue
		}
		j := i + 1
		for j < len(ids) && firstDashSegment(ids[j]) == firstTok {
			j++
		}
		if j-i < 2 {
			parts = append(parts, ids[i])
			i++
			continue
		}
		// Within ids[i:j], find the deepest dash-segmented prefix
		// shared by ALL members.
		prefix := deepestSharedPrefix(ids[i:j])
		parts = append(parts, prefix+"-*")
		i = j
	}
	return strings.Join(parts, " ")
}

// firstDashSegment returns the substring of id before the first
// dash, or "" if the ID has no dash.
func firstDashSegment(id string) string {
	if idx := strings.Index(id, "-"); idx > 0 {
		return id[:idx]
	}
	return ""
}

// deepestSharedPrefix walks dash-segmented prefixes and returns the
// longest one that all members of ids share. Assumes len(ids) >= 1
// and that the first dash segment is non-empty.
//
// Example: ["pam-faillock-deny", "pam-faillock-silent",
// "pam-faillock-unlock-time"] → "pam-faillock". Adding
// "pam-pwhistory-remember" to the input → "pam".
func deepestSharedPrefix(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	// Tokenize each ID by dashes.
	tokens := make([][]string, len(ids))
	for i, id := range ids {
		tokens[i] = strings.Split(id, "-")
	}
	// Walk segments left to right; stop when any ID diverges.
	var prefix []string
	for depth := 0; ; depth++ {
		if depth >= len(tokens[0]) {
			break
		}
		seg := tokens[0][depth]
		allMatch := true
		for j := 1; j < len(tokens); j++ {
			if depth >= len(tokens[j]) || tokens[j][depth] != seg {
				allMatch = false
				break
			}
		}
		if !allMatch {
			break
		}
		prefix = append(prefix, seg)
	}
	if len(prefix) == 0 {
		return ""
	}
	return strings.Join(prefix, "-")
}

// progressBar renders an ASCII progress bar showing pass/warn/fail
// proportions. Width is total character count; passed cells get '#',
// warned get '~', failed get 'x', and unaccounted-for cells get '.'.
//
// Example for 87 pass, 8 fail, 5 warn at width 60:
//
//	####################...#####xxx~~
func progressBar(pass, warn, fail, width int) string {
	total := pass + warn + fail
	if total == 0 {
		return strings.Repeat(".", width)
	}
	// Compute cell counts proportionally; round so the sum equals
	// width.
	pCells := pass * width / total
	wCells := warn * width / total
	fCells := width - pCells - wCells
	if fCells < 0 {
		fCells = 0
	}
	return strings.Repeat("#", pCells) +
		strings.Repeat("~", wCells) +
		strings.Repeat("x", fCells)
}

// blankLine emits a newline. Centralized so layout adjustments touch
// one site.
func blankLine(w io.Writer) error {
	_, err := fmt.Fprintln(w)
	return err
}
