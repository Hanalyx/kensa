package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/internal/coverage"
	"github.com/Hanalyx/kensa-go/internal/output"
)

// runListFrameworks handles `kensa list frameworks
// --rules-dir DIR [--format {text,json}]` (C-046). One row
// per framework_id present in the loaded corpus, sorted
// alphabetically.
func runListFrameworks(ctx context.Context, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"rules-dir": true, "format": true,
	})

	fs := pflag.NewFlagSet("list frameworks", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		rulesDir string
		format   string
		quiet    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory of rule YAMLs to scan (required)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printListFrameworksUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa list frameworks --help'", err)
	}
	if showHelp {
		printListFrameworksUsage(os.Stdout, fs)
		return nil
	}

	if rulesDir == "" {
		return NewUsageError("--rules-dir DIR is required to scan a rule corpus")
	}
	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}

	rules, err := loadRulesFromDirOrFiles(rulesDir, nil, nil)
	if err != nil {
		return err
	}

	summaries := coverage.ListFrameworks(rules)

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		// Wrap in a top-level object so future fields
		// (e.g. corpus_size, generated_at) can be added
		// without breaking shape compatibility.
		envelope := struct {
			Frameworks []coverage.FrameworkSummary `json:"frameworks"`
		}{Frameworks: summaries}
		return jw.WriteJSONValue(out, envelope)
	}
	writeListFrameworksText(out, summaries)
	return nil
}

// writeListFrameworksText renders the C-046 table. ASCII
// separators (LANG=C compatible per the C-045 fix). Column
// widths chosen to fit common framework_id forms (cis_rhel9,
// nist_800_53, stig_rhel9, pci_dss).
//
// Column header is "rules ref'g" (rules referencing) NOT
// "rules" — peer review caught the misread risk where
// "nist_800_53 ... 516 rules" reads as "we have 516 NIST
// rules" when really it's "516 corpus rules reference
// nist_800_53 at all". A footer legend disambiguates.
func writeListFrameworksText(w io.Writer, frameworks []coverage.FrameworkSummary) {
	fmt.Fprintln(w, "kensa list frameworks")
	if len(frameworks) == 0 {
		fmt.Fprintln(w, "  (no framework references in the loaded corpus)")
		return
	}
	fmt.Fprintf(w, "  %d framework(s)\n\n", len(frameworks))
	fmt.Fprintln(w, "  framework             controls   rules ref'g")
	fmt.Fprintln(w, "  --------------------  --------  ------------")
	for _, f := range frameworks {
		fmt.Fprintf(w, "  %-20s  %8d  %12d\n", f.FrameworkID, f.Controls, f.Rules)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  columns: distinct controls referenced under this framework;")
	fmt.Fprintln(w, "           distinct rules in the corpus referencing this framework")
}

func printListFrameworksUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa list frameworks --rules-dir DIR [flags]

List every framework_id present in the loaded rule corpus along
with the count of distinct controls referenced and the count of
distinct rules referencing each.

Counts are DISTINCT, not entry-counts: if three rules all map to
CIS RHEL9 5.1.12, that's "1 control, 3 rules" — not "3 controls".
The numbers are corpus-internal; without an external control
catalog (future deliverable) they don't yield a coverage %%.

Flags:
%s
Examples:
  kensa list frameworks --rules-dir /path/to/rules
  kensa list frameworks -r /path/to/rules --format json
`, fs.FlagUsages())
}
