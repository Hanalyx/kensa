package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/internal/coverage"
	"github.com/Hanalyx/kensa-go/internal/output"
)

// runCoverageReport handles `kensa coverage --framework
// FRAMEWORK --rules-dir DIR` (C-045). The new behavior shipped
// today is gated on `--framework`; without it, dispatch falls
// through to the C-044 deprecation alias path that runs the
// mechanism listing.
//
// --rules-dir is required (no default rule-dir bundled in the
// binary; that's an M7 follow-up). --framework is required by
// definition — aggregating across frameworks would mix CIS
// decimal IDs, NIST AC-codes, and STIG V-IDs in one column,
// rendering the output unreadable.
func runCoverageReport(args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"framework": true, "rules-dir": true, "format": true,
	})

	fs := pflag.NewFlagSet("coverage", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp  bool
		framework string
		rulesDir  string
		format    string
		full      bool
		quiet     bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	registerFrameworkFlag(fs, &framework)
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory of rule YAMLs to scan (required)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVar(&full, "full", false, "in text output, show every rule ID per control (default: truncate to first 3)")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printCoverageReportUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa coverage --help'", err)
	}
	if showHelp {
		printCoverageReportUsage(os.Stdout, fs)
		return nil
	}

	if framework == "" {
		return NewUsageError("--framework is required for the coverage report (e.g. --framework cis_rhel9)")
	}
	if rulesDir == "" {
		return NewUsageError("--rules-dir DIR is required to scan a rule corpus")
	}
	// Format is text or json — anything else is silently rendered
	// as text in many CLIs, but here that hides typos. Validate
	// up front.
	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}

	rules, err := loadRulesFromDirOrFiles(rulesDir, nil, nil)
	if err != nil {
		return err
	}

	available := availableFrameworks(rules)
	canonical, err := validateFramework(framework, available)
	if err != nil {
		return WrapUsageError("--framework", err)
	}

	report := coverage.ComputeReport(canonical, rules)

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		return jw.WriteJSONValue(out, report)
	}
	writeCoverageText(out, report, full)
	return nil
}

// writeCoverageText renders CoverageReport in the operator-facing
// text format. Layout is two-column key:value at the header, then
// a per-control table sorted by control_id (already sorted by
// ComputeReport — this is a render-only function).
//
// Labels disambiguate operator misreads:
//   - "rules in corpus"  not "rules scanned" (post-load count)
//   - "rules referencing FRAMEWORK" not "rules matching"
//     (avoids "matching" reading as "passed")
//   - "controls with rules" not "controls mapped" (avoids
//     reading the numerator as a coverage percentage; the
//     denominator catalog is a future deliverable)
//
// ASCII separators (not Unicode box-drawing) so output renders
// cleanly under LANG=C, journalctl with non-UTF-8 locale,
// Cygwin without UTF-8 console, etc.
//
// full=true disables the truncate-to-3 rule-ID inline display
// and lists every rule per control. Default truncates so wide
// corpora produce a readable summary; --full is the audit-mode
// escape hatch.
func writeCoverageText(w io.Writer, r coverage.CoverageReport, full bool) {
	fmt.Fprintf(w, "kensa coverage --framework %s\n", r.Framework)
	fmt.Fprintf(w, "  rules in corpus:           %d\n", r.RulesScanned)
	fmt.Fprintf(w, "  rules referencing %-9s %d\n", r.Framework+":", r.RulesMatching)
	fmt.Fprintf(w, "  controls with rules:       %d  (numerator only — framework total not bundled)\n", r.ControlsMapped)
	if r.ControlsMapped == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  control            rules  rule IDs")
	fmt.Fprintln(w, "  -----------------  -----  -----------------")
	for _, c := range r.Controls {
		shown := c.Rules
		suffix := ""
		const maxInline = 3
		if !full && len(c.Rules) > maxInline {
			shown = c.Rules[:maxInline]
			suffix = fmt.Sprintf(", +%d more", len(c.Rules)-maxInline)
		}
		fmt.Fprintf(w, "  %-17s  %5d  %s%s\n",
			c.ControlID, c.RuleCount, strings.Join(shown, ", "), suffix)
	}
	if !full {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  (rule IDs truncated to first 3 per control; pass --full for the complete list)")
	}
}

// printCoverageReportUsage writes the C-045 help text. Distinct
// from printMechanismsUsage because the surfaces have different
// flags and different positional expectations.
func printCoverageReportUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa coverage --framework FRAMEWORK --rules-dir DIR [flags]

Report which controls in the named framework are referenced by
rules in the loaded corpus. The output lists every distinct
control referenced by at least one rule, plus the rule IDs that
map to it.

NUMERATOR ONLY: this report shows controls with rules, not the
framework's full control set. A "212 / 318 covered (66.7%%)"
reading would require an external control catalog kensa-go
does not bundle today; that's a future deliverable.

Today this report is opt-in via --framework; without --framework
'kensa coverage' remains the deprecated alias for 'kensa mechanisms'
(see 'kensa coverage --help' without --framework for the alias).

Flags:
%s
Examples:
  kensa coverage --framework cis_rhel9 --rules-dir /path/to/rules
  kensa coverage -f nist_800_53 -r /path/to/rules --format json
  kensa coverage -f cis_rhel9 -r /path/to/rules --full         # all rule IDs per control
`, fs.FlagUsages())
}

// hasFrameworkFlag uses a permissive pflag pre-parse to detect
// whether --framework / -f is on argv. Used at the dispatch
// site to pick between the C-045 coverage-report path and the
// C-044 mechanism-alias path.
//
// Why pflag rather than a hand-rolled scanner: pflag accepts
// merged-short-bool forms like `-qfcis_rhel9` (parses as
// `-q` plus `-f=cis_rhel9`). A naive prefix scan misclassifies
// these. Letting pflag itself decide ensures the dispatch
// agrees with what the runCoverageReport flagset will see.
//
// ParseErrorsAllowlist.UnknownFlags=true so unknown flags don't
// abort the detection — we don't care about other flags here,
// only whether --framework was set. POSIX end-of-options "--"
// is honored by pflag automatically.
func hasFrameworkFlag(args []string) bool {
	fs := pflag.NewFlagSet("framework-detector", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	var fw string
	fs.StringVarP(&fw, "framework", ShortFramework, "", "")
	_ = fs.Parse(args)
	return fs.Changed("framework")
}

// hasHelpFlag uses the same permissive pre-parse to detect
// `--help` / `-h`. Used at the dispatch site so we can emit
// the C-044 repurpose warning even on the new path's --help —
// operators reading docs to learn the surface need to see the
// upcoming v0.2 semantic flip once.
func hasHelpFlag(args []string) bool {
	fs := pflag.NewFlagSet("help-detector", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	var help bool
	fs.BoolVarP(&help, "help", ShortHelp, false, "")
	_ = fs.Parse(args)
	return fs.Changed("help")
}
