package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/internal/info"
	"github.com/Hanalyx/kensa/internal/output"
)

// runInfo handles `kensa info` (C-047). Four mode selectors:
// --rule, --control, --list-controls, positional QUERY. Modes
// are pairwise exclusive where they would conflict (see C-02
// in spec). --cis/--stig/--nist + --rhel act as filters that
// narrow the search corpus.
//
// Exit-code contract:
//   - bad invocation                   → 2 (usage error)
//   - syntactically valid but no match → 1 (runtime; ErrNotFound)
//   - success                          → 0
func runInfo(ctx context.Context, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"rule": true, "control": true, "list-controls": true,
		"rules-dir": true, "format": true, "rhel": true,
	})

	fs := pflag.NewFlagSet("info", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp    bool
		ruleID      string
		controlSpec string
		listCtrls   string
		rulesDir    string
		format      string
		quiet       bool
		cisFamily   bool
		stigFamily  bool
		nistFamily  bool
		rhel        int
		limit       int
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVar(&ruleID, "rule", "", "show details for a single rule by ID (long-only; -r is --rules-dir)")
	fs.StringVar(&controlSpec, "control", "", "show rules mapping FRAMEWORK:ID (e.g. cis_rhel9:5.1.12)")
	fs.StringVarP(&listCtrls, "list-controls", "L", "", "list every control referenced under FRAMEWORK with rule counts")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory of rule YAMLs to scan (required)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text, json, or jsonl (jsonl is QUERY mode only)")
	fs.BoolVar(&cisFamily, "cis", false, "filter to CIS family (cis_rhel8, cis_rhel9, cis_rhel10)")
	fs.BoolVar(&stigFamily, "stig", false, "filter to STIG family (stig_rhel8, stig_rhel9, stig_rhel10)")
	fs.BoolVar(&nistFamily, "nist", false, "filter to NIST family (nist_800_53; not RHEL-versioned, so does NOT compose with --rhel)")
	fs.IntVar(&rhel, "rhel", 0, "filter by RHEL version (8, 9, or 10); composes with --cis/--stig (not --nist)")
	fs.IntVar(&limit, "limit", 100, "cap text output rows (search + list-controls modes); 0 = unlimited")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printInfoUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa info --help'", err)
	}
	if showHelp {
		printInfoUsage(os.Stdout, fs)
		return nil
	}

	switch format {
	case "text", "json", "jsonl":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text', 'json', or 'jsonl'", format))
	}
	if limit < 0 {
		return NewUsageError(fmt.Sprintf("--limit %d: must be ≥ 0 (0 = unlimited)", limit))
	}

	// Mode mux. The four primary mode selectors (--rule,
	// --control, --list-controls, positional QUERY) are
	// pairwise mutually exclusive: pick exactly one. QUERY
	// is the search-mode entry; combining it with --rule
	// or --control is rejected because the implementation
	// would have to filter inside an already-narrow axis,
	// which an operator can do with `kensa info QUERY
	// --cis` (search + family filter) or `... | grep` more
	// cleanly.
	queryArgs := fs.Args()
	hasQuery := len(queryArgs) > 0
	var modes []string
	if ruleID != "" {
		modes = append(modes, "--rule")
	}
	if controlSpec != "" {
		modes = append(modes, "--control")
	}
	if listCtrls != "" {
		modes = append(modes, "--list-controls")
	}
	if hasQuery {
		modes = append(modes, "QUERY")
	}
	if len(modes) > 1 {
		return NewUsageError(fmt.Sprintf(
			"%s: pick exactly one (these are different lookup shapes, not filters that compose)",
			strings.Join(modes, ", ")))
	}
	// Operator must pick at least one axis. When BOTH --rules-dir
	// AND mode are missing, surface both in one message — the
	// operator running `kensa info` cold shouldn't have to retry
	// twice to learn what the command wants.
	if len(modes) == 0 && rulesDir == "" {
		return NewUsageError("missing --rules-dir DIR and a mode (--rule, --control, --list-controls, or QUERY)")
	}
	if len(modes) == 0 {
		return NewUsageError("specify a mode: --rule R, --control FRAMEWORK:ID, --list-controls FRAMEWORK, or a positional QUERY")
	}
	if rulesDir == "" {
		return NewUsageError("--rules-dir DIR is required")
	}

	// C-052: jsonl is for QUERY mode only. Document-shaped
	// modes (--rule, --control, --list-controls) emit single
	// objects; jsonl-encoding a document is shape-violation.
	// Check BEFORE the corpus load so the operator sees a
	// clean usage error without unrelated rule-warning noise.
	if format == "jsonl" && (ruleID != "" || controlSpec != "" || listCtrls != "") {
		return NewUsageError(
			"--format jsonl is for the QUERY (search) mode only; --rule, --control, and --list-controls emit single documents — use --format json for those")
	}

	// Family-shortcut mux + rhel validation. --cis + --stig is
	// rejected; --rhel must be one of the allowed values.
	familyPrefix, err := resolveFamilyPrefix(cisFamily, stigFamily, nistFamily)
	if err != nil {
		return err
	}
	if rhel != 0 && rhel != 8 && rhel != 9 && rhel != 10 {
		return NewUsageError(fmt.Sprintf("--rhel %d: must be 8, 9, or 10", rhel))
	}
	// --nist + --rhel is rejected: nist_800_53 is unversioned
	// (flat-list framework, no _rhel<V> suffix). Allowing the
	// combo would silently mutate the prefix to "nist_rhel9"
	// which matches no rule. Forcing the operator to pick keeps
	// the failure mode loud.
	if nistFamily && rhel != 0 {
		return NewUsageError("--nist does not compose with --rhel (nist_800_53 is unversioned)")
	}
	// --cis --rhel 9 → narrow family prefix to cis_rhel9 (exact
	// version pin). --rhel without family stays as a Platforms
	// filter on the rule (handled inside SearchRules via Rhel).
	if familyPrefix != "" && rhel != 0 {
		familyPrefix = strings.TrimSuffix(familyPrefix, "_") + fmt.Sprintf("_rhel%d", rhel)
	}

	rules, err := loadRulesFromDirOrFiles(rulesDir, nil, nil)
	if err != nil {
		return err
	}

	out := bodyOut(quiet)
	jw, _ := output.JSONValueWriterFor("json")

	switch {
	case ruleID != "":
		details, err := info.DescribeRule(ruleID, rules)
		if err != nil {
			return err // ErrNotFound → exit 1 via runCLI
		}
		if format == "json" {
			return jw.WriteJSONValue(out, details)
		}
		writeRuleDetailsText(out, details)
		return nil

	case controlSpec != "":
		framework, control, ok := strings.Cut(controlSpec, ":")
		if !ok || framework == "" || control == "" {
			return NewUsageError(fmt.Sprintf("--control %q: must be FRAMEWORK:CONTROL_ID (e.g. cis_rhel9:5.1.12)", controlSpec))
		}
		match, err := info.RulesForControl(framework, control, rules)
		if err != nil {
			return err
		}
		if format == "json" {
			return jw.WriteJSONValue(out, match)
		}
		writeControlMatchText(out, match)
		return nil

	case listCtrls != "":
		listing, err := info.ListFrameworkControls(listCtrls, rules)
		if err != nil {
			return err
		}
		if format == "json" {
			return jw.WriteJSONValue(out, listing)
		}
		writeControlListingText(out, listing, limit)
		return nil
	}

	// Free-text search (with or without filters).
	query := strings.Join(queryArgs, " ")
	hits := info.SearchRules(query, info.SearchFilters{
		FamilyPrefix: familyPrefix,
		Rhel:         rhel,
	}, rules)
	if format == "json" {
		envelope := struct {
			Query string           `json:"query"`
			Hits  []info.SearchHit `json:"hits"`
		}{Query: query, Hits: hits}
		return jw.WriteJSONValue(out, envelope)
	}
	if format == "jsonl" {
		// C-052: one compact SearchHit per line. Matches the
		// per-element shape of the JSON envelope's `hits`
		// array (parsed-shape equivalence locked by
		// TestRunInfo_QueryJSONLShapeMatchesJSON).
		enc := json.NewEncoder(out)
		for _, h := range hits {
			if err := enc.Encode(h); err != nil {
				return err
			}
		}
		return nil
	}
	writeSearchHitsText(out, query, hits, limit)
	return nil
}

// resolveFamilyPrefix maps the --cis/--stig/--nist booleans
// to a framework_id prefix. Mutual exclusion: at most one can
// be set; combining two raises a usage error.
func resolveFamilyPrefix(cis, stig, nist bool) (string, error) {
	var families []string
	if cis {
		families = append(families, "--cis")
	}
	if stig {
		families = append(families, "--stig")
	}
	if nist {
		families = append(families, "--nist")
	}
	if len(families) > 1 {
		return "", NewUsageError(fmt.Sprintf(
			"%s are mutually exclusive — pick one framework family", strings.Join(families, " + ")))
	}
	switch {
	case cis:
		return "cis_", nil
	case stig:
		return "stig_", nil
	case nist:
		return "nist_", nil
	default:
		return "", nil
	}
}

func writeRuleDetailsText(w io.Writer, r *info.RuleDetails) {
	fmt.Fprintf(w, "Rule: %s\n", r.ID)
	fmt.Fprintf(w, "  title:       %s\n", r.Title)
	fmt.Fprintf(w, "  severity:    %s\n", r.Severity)
	if r.Category != "" {
		fmt.Fprintf(w, "  category:    %s\n", r.Category)
	}
	if len(r.Tags) > 0 {
		fmt.Fprintf(w, "  tags:        %s\n", strings.Join(r.Tags, ", "))
	}
	if r.Description != "" {
		fmt.Fprintf(w, "  description: %s\n", oneLine(r.Description))
	}
	if len(r.Platforms) > 0 {
		fmt.Fprintln(w, "  platforms:")
		for _, p := range r.Platforms {
			fmt.Fprintf(w, "    - %s\n", formatPlatform(p))
		}
	}
	if len(r.FrameworkRefs) > 0 {
		fmt.Fprintln(w, "  framework refs:")
		for _, ref := range r.FrameworkRefs {
			fmt.Fprintf(w, "    - %s:%s\n", ref.FrameworkID, ref.ControlID)
		}
	}
}

// formatPlatform renders a Platform with operator-friendly
// version expression. Zero MinVersion / MaxVersion in the rule
// YAML means "no bound" — rendering them as `(min=8, max=0)`
// reads as "max version 0" (i.e. RHEL 0), which is the wrong
// signal. Cases:
//
//	min=0, max=0  → "<family> (any version)"
//	min=N, max=0  → "<family> >= N"
//	min=0, max=N  → "<family> <= N"
//	min=N, max=N  → "<family> N"
//	min=A, max=B  → "<family> A-B"
func formatPlatform(p info.PlatformSummary) string {
	switch {
	case p.MinVersion == 0 && p.MaxVersion == 0:
		return fmt.Sprintf("%s (any version)", p.Family)
	case p.MaxVersion == 0:
		return fmt.Sprintf("%s >= %d", p.Family, p.MinVersion)
	case p.MinVersion == 0:
		return fmt.Sprintf("%s <= %d", p.Family, p.MaxVersion)
	case p.MinVersion == p.MaxVersion:
		return fmt.Sprintf("%s %d", p.Family, p.MinVersion)
	default:
		return fmt.Sprintf("%s %d-%d", p.Family, p.MinVersion, p.MaxVersion)
	}
}

func writeControlMatchText(w io.Writer, m *info.ControlMatch) {
	fmt.Fprintf(w, "Control: %s:%s\n", m.FrameworkID, m.ControlID)
	fmt.Fprintf(w, "  %d rule(s) referencing this control:\n", len(m.Rules))
	for _, id := range m.Rules {
		fmt.Fprintf(w, "    - %s\n", id)
	}
}

func writeControlListingText(w io.Writer, l *info.ControlListing, limit int) {
	fmt.Fprintf(w, "Framework: %s\n", l.FrameworkID)
	fmt.Fprintf(w, "  %d control(s)\n\n", len(l.Controls))
	fmt.Fprintln(w, "  control            rules")
	fmt.Fprintln(w, "  -----------------  ------")
	shown := l.Controls
	truncated := false
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
		truncated = true
	}
	for _, c := range shown {
		fmt.Fprintf(w, "  %-17s  %5d\n", c.ControlID, c.RuleCount)
	}
	if truncated {
		fmt.Fprintf(w, "\n  (showing first %d of %d controls; pass --limit 0 for the full list)\n",
			len(shown), len(l.Controls))
	}
}

func writeSearchHitsText(w io.Writer, query string, hits []info.SearchHit, limit int) {
	if query != "" {
		fmt.Fprintf(w, "Search: %q\n", query)
	} else {
		fmt.Fprintln(w, "Search: (no query — listing all rules under filters)")
	}
	fmt.Fprintf(w, "  %d hit(s)\n", len(hits))
	if len(hits) == 0 {
		return
	}
	shown := hits
	truncated := false
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
		truncated = true
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  rule                                severity   title")
	fmt.Fprintln(w, "  ----------------------------------  --------   -----")
	for _, h := range shown {
		fmt.Fprintf(w, "  %-34s  %-8s   %s\n", h.ID, h.Severity, oneLine(h.Title))
	}
	if truncated {
		fmt.Fprintf(w, "\n  (showing first %d of %d hits; pass --limit 0 for the full list)\n",
			len(shown), len(hits))
	}
}

// oneLine collapses internal newlines/whitespace so multi-line
// descriptions render on a single output row.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func printInfoUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa info [MODE] --rules-dir DIR [filters] [QUERY]

Multi-criteria lookup over a loaded rule corpus. Pick ONE mode:

  --rule RULE_ID                 single-rule details
  --control FRAMEWORK:ID         rules mapping a specific control
  --list-controls FRAMEWORK      list controls under a framework with rule counts
  QUERY (positional)             case-insensitive substring search over title + description

Filters (compose with QUERY; --cis/--stig/--nist also narrow within --rule/--control):
  --cis | --stig | --nist        framework-family shortcut (mutually exclusive)
  --rhel 8 | 9 | 10              RHEL version (composes with --cis/--stig; standalone filters Platforms)

%s

Examples:
  kensa info ssh --rules-dir /path/to/rules                   # search "ssh" in titles + descriptions
  kensa info ssh --cis --rhel 9 --rules-dir /path/to/rules    # SSH rules in CIS RHEL9
  kensa info --rule sysctl-ip-forward-disabled --rules-dir /path/to/rules
  kensa info --control cis_rhel9:5.1.12 --rules-dir /path/to/rules
  kensa info --list-controls cis_rhel9 --rules-dir /path/to/rules
  kensa info --cis --rhel 9 --rules-dir /path/to/rules        # every CIS RHEL9 rule (no QUERY)
  kensa info file --rules-dir /path/to/rules --limit 0        # show all hits (no truncation)
`, formatGroupedUsages(fs, infoFlagGroups))
}
