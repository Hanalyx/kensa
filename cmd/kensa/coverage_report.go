package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/internal/coverage"
	"github.com/Hanalyx/kensa/internal/output"
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
	var fromScan string
	fs.StringVar(&fromScan, "from-scan", "", "scan report JSON; computes the 800-171 denominator for that fleet")

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
	// A framework gets a denominator when it ships an objective catalog, and
	// keeps the numerator-only policy when it does not. That is the whole
	// condition: asking the catalog registry rather than naming a framework
	// keeps the next catalog from adding a branch here. Numerator-only is not
	// a limitation but a refusal to invent a denominator for a framework whose
	// control set kensa cannot enumerate (see cli-framework-coverage).
	if coverage.HasObjectiveCatalog(framework) {
		switch format {
		case "text", "json":
		default:
			return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
		}
		return runNIST800171Coverage(fromScan, format, quiet)
	}
	if fromScan != "" {
		return NewUsageError("--from-scan applies only to a framework that ships an " +
			"objective catalog; the rest report the controls the corpus cites, with no " +
			"denominator to compute against")
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

	introVars, err := introspectionVars()
	if err != nil {
		return err
	}
	rules, _, err := loadRulesFromDirOrFiles(rulesDir, nil, introVars)
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

// printCoverageReportUsage writes the `kensa coverage` help text. This is the
// only coverage help surface: the command no longer has an alias mode, so
// there is nothing to disambiguate.
func printCoverageReportUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa coverage --framework FRAMEWORK [flags]

Report which controls in the named framework are covered by the rule corpus.

--framework is required. There is no default framework, because the frameworks
report different things and aggregating them would produce a number that means
nothing.

--rules-dir is required for a framework whose controls kensa reads from the
corpus. It is NOT required for a framework that ships an embedded objective
catalog: today that is nist_800_171, which reports against its own catalog and
needs no corpus directory.

NUMERATOR ONLY for corpus-read frameworks: the report lists controls that have
rules, not the framework's full control set. A "212 / 318 covered" reading
would need an external control catalog kensa does not bundle. A framework with
an embedded objective catalog does report a denominator, because kensa can
enumerate its controls.

To list handler mechanisms, run 'kensa mechanisms'.

Flags:
%s
Examples:
  kensa coverage --framework cis_rhel9 --rules-dir /path/to/rules
  kensa coverage --framework nist_800_171                    # embedded catalog
  kensa coverage --framework nist_800_171 --from-scan scan.json
  kensa coverage -f cis_rhel9 -r /path/to/rules --full       # all rule IDs
`, fs.FlagUsages())
}

// hasFrameworkFlag uses a permissive pflag pre-parse to detect
// whether --framework / -f is on argv. The coverage dispatch no longer needs
// it, but `mechanisms` does: --framework there is a usage error pointing the
// operator at `kensa coverage`, and that rejection has to agree with what the
// coverage flagset would have accepted.
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
