// Command kensa-catalog builds and queries the compliance-benchmark control
// catalog: a single SQLite file ingested from authoritative sources (DISA STIG
// XCCDF today; NIST 800-53 OSCAL, the DISA CCI list, and CIS facts next). It is a
// dev and CI authoring tool, not a shipped binary.
//
// Usage:
//
//	kensa-catalog -db catalog.db ingest stig <os> <release> <xccdf-path>
//	kensa-catalog -db catalog.db ingest coverage <corpus-coverage.json>
//	kensa-catalog -db catalog.db coverage [framework]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/Hanalyx/kensa/internal/catalog"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run parses flags and dispatches a subcommand, returning the process exit code.
// It is the testable entry point; main is the only os.Exit caller. --help, -h, and
// the "help" subcommand print full usage to stdout and exit 0.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kensa-catalog", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // render usage and errors ourselves, to the right stream
	dbPath := fs.String("db", "catalog.db", "path to the catalog SQLite file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) { // -h / -help / --help
			usage(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "kensa-catalog:", err)
		usage(stderr)
		return 2
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "help" {
		usage(stdout)
		return 0
	}
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}
	// Validate the subcommand before opening the store, so an unknown command is a
	// clean usage error that never creates a stray database file.
	known := map[string]bool{
		"build": true, "ingest": true, "coverage": true, "nist": true, "missing": true,
		"drift": true, "control": true, "verified": true, "crosswalk": true,
		"baseline": true, "check": true,
	}
	if !known[rest[0]] {
		fmt.Fprintf(stderr, "kensa-catalog: unknown command %q\n", rest[0])
		usage(stderr)
		return 2
	}

	ctx := context.Background()
	store, err := catalog.Open(ctx, *dbPath)
	if err != nil {
		fmt.Fprintln(stderr, "kensa-catalog:", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	switch rest[0] {
	case "build":
		runBuild(ctx, store, rest[1:])
	case "ingest":
		runIngest(ctx, store, rest[1:])
	case "coverage":
		runCoverage(ctx, store, rest[1:])
	case "nist":
		runNIST(ctx, store, rest[1:])
	case "missing":
		runMissing(ctx, store, rest[1:])
	case "drift":
		runDrift(ctx, store, rest[1:])
	case "control":
		runControl(ctx, store, rest[1:])
	case "verified":
		runVerified(ctx, store, rest[1:])
	case "crosswalk":
		runCrosswalk(ctx, store, rest[1:])
	case "baseline":
		runBaseline(ctx, store)
	case "check":
		runCheck(ctx, store, rest[1:])
	default:
		return 2 // unreachable: the known-command check above gates these
	}
	return 0
}

type baselineCell struct {
	Framework string `json:"framework"`
	OS        string `json:"os"`
	Total     int    `json:"total"`
	Covered   int    `json:"covered"`
	Drifted   int    `json:"drifted"`
}

func fullMatrix(ctx context.Context, store *catalog.Store) []baselineCell {
	var out []baselineCell
	for _, fw := range []string{"stig", "cis"} {
		rows, err := store.CoverageMatrix(ctx, fw)
		if err != nil {
			fail(err)
		}
		for _, r := range rows {
			out = append(out, baselineCell{fw, r.OS, r.Total, r.Covered, r.Drifted})
		}
	}
	return out
}

// runBaseline prints the current coverage matrix as the committed baseline.
func runBaseline(ctx context.Context, store *catalog.Store) {
	out, err := json.MarshalIndent(map[string]interface{}{"cells": fullMatrix(ctx, store)}, "", " ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(out))
}

// runCheck compares the freshly built catalog against the committed baseline and
// exits non-zero if any cell lost coverage, gained drift, or changed total. This
// is the CI gate: it catches a rule that dropped a reference, a corrupted source,
// or a newly introduced stale citation, while tolerating the known existing drift.
func runCheck(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) != 1 {
		fail(fmt.Errorf("usage: check <baseline.json>"))
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		fail(err)
	}
	var base struct {
		Cells []baselineCell `json:"cells"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		fail(fmt.Errorf("parse baseline: %w", err))
	}
	want := map[string]baselineCell{}
	for _, c := range base.Cells {
		want[c.Framework+"|"+c.OS] = c
	}

	var problems []string
	for _, cur := range fullMatrix(ctx, store) {
		b, ok := want[cur.Framework+"|"+cur.OS]
		if !ok {
			continue // a newly added benchmark cell is not a regression
		}
		if cur.Total != b.Total {
			problems = append(problems, fmt.Sprintf("%s %s: benchmark total changed %d -> %d (re-baseline if intended)", cur.Framework, cur.OS, b.Total, cur.Total))
		}
		if cur.Covered < b.Covered {
			problems = append(problems, fmt.Sprintf("%s %s: coverage REGRESSED %d -> %d", cur.Framework, cur.OS, b.Covered, cur.Covered))
		}
		if cur.Drifted > b.Drifted {
			problems = append(problems, fmt.Sprintf("%s %s: drift INCREASED %d -> %d (a rule cites a control absent from the benchmark)", cur.Framework, cur.OS, b.Drifted, cur.Drifted))
		}
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "catalog drift gate:", p)
		}
		os.Exit(1)
	}
	fmt.Println("catalog drift gate: OK (no coverage regression or new drift vs baseline)")
}

func runMissing(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) != 2 {
		fail(fmt.Errorf("usage: missing <framework> <os>"))
	}
	framework, osID := args[0], args[1]
	controls, err := store.MissingControls(ctx, framework, osID)
	if err != nil {
		fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	if framework == "cis" {
		fmt.Fprintf(w, "SECTION\tLEVEL\tAUTOMATABLE\n")
		auto := 0
		for _, c := range controls {
			a := "manual"
			if c.Automatable == 1 {
				a = "automatable"
				auto++
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.ControlID, c.SecondaryID, a)
		}
		_ = w.Flush()
		fmt.Printf("\n%d missing (%d automatable) for cis %s\n", len(controls), auto, osID)
		return
	}
	fmt.Fprintf(w, "VULN-ID\tSTIG-ID\tSEVERITY\tTITLE\n")
	for _, c := range controls {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.ControlID, c.SecondaryID, c.Severity, truncate(c.Title, 70))
	}
	_ = w.Flush()
	fmt.Printf("\n%d missing for %s %s\n", len(controls), framework, osID)
}

func runDrift(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) != 2 {
		fail(fmt.Errorf("usage: drift <framework> <os>"))
	}
	drifts, err := store.DriftedCitations(ctx, args[0], args[1])
	if err != nil {
		fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "STALE-CONTROL\tCITED-BY\n")
	for _, d := range drifts {
		fmt.Fprintf(w, "%s\t%s\n", d.ControlID, strings.Join(d.Rules, ", "))
	}
	_ = w.Flush()
	fmt.Printf("\n%d stale citation(s) for %s %s — re-mapping work list\n", len(drifts), args[0], args[1])
}

func runControl(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) != 3 {
		fail(fmt.Errorf("usage: control <framework> <os> <control-id>"))
	}
	xw, err := store.ControlCrosswalk(ctx, args[0], args[1], args[2])
	if err != nil {
		fail(err)
	}
	if xw == nil {
		fail(fmt.Errorf("%s %s control %q not found in catalog", args[0], args[1], args[2]))
	}
	fmt.Printf("%s %s  %s\n", xw.Framework, xw.OS, xw.ControlID)
	if xw.SecondaryID != "" {
		fmt.Printf("  id/level:   %s\n", xw.SecondaryID)
	}
	if xw.Severity != "" {
		fmt.Printf("  severity:   %s\n", xw.Severity)
	}
	if xw.Title != "" {
		fmt.Printf("  title:      %s\n", xw.Title)
	}
	if len(xw.CCIs) > 0 {
		fmt.Printf("  CCIs:       %s\n", strings.Join(xw.CCIs, ", "))
	}
	if len(xw.NIST80053) > 0 {
		fmt.Printf("  800-53 r5:  %s\n", strings.Join(xw.NIST80053, ", "))
	}
	if len(xw.CoveringRules) > 0 {
		fmt.Printf("  covered by: %s\n", strings.Join(xw.CoveringRules, ", "))
	} else {
		fmt.Printf("  covered by: (none — missing)\n")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

type manifest struct {
	Stig []struct {
		OS, Release, File string
	} `json:"stig"`
	Cis           []string `json:"cis"`
	Nist          string   `json:"nist"`
	Cci           string   `json:"cci"`
	Verifications string   `json:"verifications"`
}

// runBuild rebuilds the whole catalog from a vendored sources tree (its
// manifest.json) plus the rule corpus, so the database is reproducible from
// committed inputs alone.
func runBuild(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) != 2 {
		fail(fmt.Errorf("usage: build <sources-dir> <rules-dir>"))
	}
	srcDir, rulesDir := args[0], args[1]
	raw, err := os.ReadFile(filepath.Join(srcDir, "manifest.json"))
	if err != nil {
		fail(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fail(fmt.Errorf("parse manifest: %w", err))
	}
	for _, b := range m.Stig {
		if _, err := store.IngestSTIG(ctx, b.OS, b.Release, filepath.Join(srcDir, b.File)); err != nil {
			fail(err)
		}
	}
	for _, c := range m.Cis {
		if _, err := store.IngestCIS(ctx, filepath.Join(srcDir, c)); err != nil {
			fail(err)
		}
	}
	if _, err := store.IngestNISTCatalog(ctx, filepath.Join(srcDir, m.Nist)); err != nil {
		fail(err)
	}
	if _, err := store.IngestCCIList(ctx, filepath.Join(srcDir, m.Cci)); err != nil {
		fail(err)
	}
	cov, err := store.IngestCoverageFromRules(ctx, rulesDir)
	if err != nil {
		fail(err)
	}
	ver := 0
	if m.Verifications != "" {
		if ver, err = store.IngestVerifications(ctx, filepath.Join(srcDir, m.Verifications)); err != nil {
			fail(err)
		}
	}
	fmt.Printf("catalog built: %d STIG + %d CIS benchmarks, NIST + CCI loaded, %d coverage citations, %d verifications, from %s\n",
		len(m.Stig), len(m.Cis), cov, ver, rulesDir)
}

func runIngest(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) == 0 {
		fail(fmt.Errorf("ingest needs a source kind: stig | coverage"))
	}
	switch args[0] {
	case "stig":
		if len(args) != 4 {
			fail(fmt.Errorf("usage: ingest stig <os> <release> <xccdf-path>"))
		}
		n, err := store.IngestSTIG(ctx, args[1], args[2], args[3])
		if err != nil {
			fail(err)
		}
		fmt.Printf("ingested %d STIG controls for %s %s\n", n, args[1], args[2])
	case "coverage":
		if len(args) != 2 {
			fail(fmt.Errorf("usage: ingest coverage <corpus-coverage.json>"))
		}
		n, err := store.IngestCoverageFromCorpus(ctx, args[1])
		if err != nil {
			fail(err)
		}
		fmt.Printf("ingested %d coverage citations (STIG + CIS)\n", n)
	case "nist":
		if len(args) != 2 {
			fail(fmt.Errorf("usage: ingest nist <nist_800-53_r5_controls.json>"))
		}
		n, err := store.IngestNISTCatalog(ctx, args[1])
		if err != nil {
			fail(err)
		}
		fmt.Printf("ingested %d NIST 800-53 rev5 catalog controls\n", n)
	case "cci":
		if len(args) != 2 {
			fail(fmt.Errorf("usage: ingest cci <cci_800-53_r5_edges.json>"))
		}
		n, err := store.IngestCCIList(ctx, args[1])
		if err != nil {
			fail(err)
		}
		fmt.Printf("ingested %d CCI-to-800-53-rev5 edges\n", n)
	case "cis":
		if len(args) != 2 {
			fail(fmt.Errorf("usage: ingest cis <cis_facts_<os>.json>"))
		}
		n, err := store.IngestCIS(ctx, args[1])
		if err != nil {
			fail(err)
		}
		fmt.Printf("ingested %d CIS recommendations (facts only)\n", n)
	case "verifications":
		if len(args) != 2 {
			fail(fmt.Errorf("usage: ingest verifications <verifications.json>"))
		}
		n, err := store.IngestVerifications(ctx, args[1])
		if err != nil {
			fail(err)
		}
		fmt.Printf("ingested %d functional verifications\n", n)
	default:
		fail(fmt.Errorf("unknown ingest kind %q", args[0]))
	}
}

func runCrosswalk(ctx context.Context, store *catalog.Store, args []string) {
	if len(args) != 2 {
		fail(fmt.Errorf("usage: crosswalk <framework> <os>"))
	}
	r, err := store.Crosswalk(ctx, args[0], args[1])
	if err != nil {
		fail(err)
	}
	if r.Total == 0 {
		fail(fmt.Errorf("no %s benchmark loaded for %s", args[0], args[1]))
	}
	pct := func(n int) float64 { return 100 * float64(n) / float64(r.Total) }
	fmt.Printf("%s %s: %d controls\n", r.Framework, r.OS, r.Total)
	fmt.Printf("  covered:  %3d (%.0f%%)   a rule already cites this control\n", r.Covered, pct(r.Covered))
	fmt.Printf("  extend:   %3d (%.0f%%)   a rule's check target matches; extend it to this OS\n", r.Extend, pct(r.Extend))
	fmt.Printf("  net-new:  %3d (%.0f%%)   no matching rule target; genuine authoring\n", r.NetNew, pct(r.NetNew))
	fmt.Printf("  reuse (covered+extend): %d/%d = %.0f%%\n", r.Covered+r.Extend, r.Total, pct(r.Covered+r.Extend))
	if len(r.ExtendList) > 0 {
		fmt.Println("\nExtend candidates (control -> matching rule via target):")
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		for _, e := range r.ExtendList {
			fmt.Fprintf(w, "  %s\t%s:%s\t-> %s\t%s\n", e.ControlID, e.Kind, e.Value, e.Rule, truncate(e.Title, 44))
		}
		_ = w.Flush()
	}
}

func runVerified(ctx context.Context, store *catalog.Store, args []string) {
	osFilter := ""
	if len(args) > 0 {
		osFilter = args[0]
	}
	rows, err := store.VerifiedRules(ctx, osFilter)
	if err != nil {
		fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "OS\tRULE\tSCOPE\tMAPPED\tHOST\tDATE\n")
	unmapped := 0
	for _, r := range rows {
		m := "yes"
		if !r.Mapped {
			m = "NO (awaiting benchmark)"
			unmapped++
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.OS, r.RuleID, r.Scope, m, r.Host, r.VerifiedAt)
	}
	_ = w.Flush()
	fmt.Printf("\n%d verification(s); %d functionally proven but not yet benchmark-mapped.\n", len(rows), unmapped)
}

func runNIST(ctx context.Context, store *catalog.Store, _ []string) {
	rows, total, err := store.DerivedNISTByFamily(ctx)
	if err != nil {
		fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "FAMILY\tTOUCHED\tIN-CATALOG\n")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%d\t%d\n", strings.ToUpper(r.Family), r.Touched, r.InCatalog)
	}
	_ = w.Flush()
	fmt.Printf("\n%d distinct 800-53 rev5 controls touched (derived from covered STIG CCIs).\n", total)
	fmt.Println("This is controls-touched, not catalog coverage: most of 800-53 is procedural and out of host scope.")
}

func runCoverage(ctx context.Context, store *catalog.Store, args []string) {
	framework := "stig"
	if len(args) > 0 {
		framework = args[0]
	}
	rows, err := store.CoverageMatrix(ctx, framework)
	if err != nil {
		fail(err)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "OS\tRELEASE\tTOTAL\tCOVERED\tMISSING\tDRIFT\tCOV%%\tVERIF\tVERIF%%\n")
	for _, r := range rows {
		pct, vpct := 0.0, 0.0
		if r.Total > 0 {
			pct = 100 * float64(r.Covered) / float64(r.Total)
			vpct = 100 * float64(r.Verified) / float64(r.Total)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%.1f\t%d\t%.1f\n",
			r.OS, r.Version, r.Total, r.Covered, r.Missing, r.Drifted, pct, r.Verified, vpct)
	}
	_ = w.Flush()
	fmt.Fprintln(os.Stderr, "COVERED = a rule cites the control (citation ceiling); "+
		"VERIF = covered AND a covering rule is live-verified on that exact OS (trustworthy floor).")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `kensa-catalog — compliance-benchmark control catalog (dev tool)

Builds and queries a SQLite catalog of CIS/STIG/NIST-800-53 controls and their
cross-references. Most use is via 'make catalog' (build) then the query verbs.

Flags:
  -db PATH      catalog SQLite file (default "catalog.db")
  -h, --help    show this help and exit

Build:
  kensa-catalog -db PATH build <sources-dir> <rules-dir>   rebuild from vendored sources + rules

Query (view) the catalog:
  kensa-catalog -db PATH coverage [framework]              covered/missing/drift + verified-coverage per OS (stig|cis)
  kensa-catalog -db PATH nist                              derived 800-53 r5 surface, per family
  kensa-catalog -db PATH missing <framework> <os>          controls no rule covers (the backlog)
  kensa-catalog -db PATH drift   <framework> <os>          stale references (re-mapping list)
  kensa-catalog -db PATH control <framework> <os> <id>     full crosswalk for one control
  kensa-catalog -db PATH verified [os]                     rules functionally proven on an OS (+ mapped?)
  kensa-catalog -db PATH crosswalk <framework> <os>        classify controls covered/extend/net-new
  kensa-catalog -db PATH baseline                          dump the matrix as JSON
  kensa-catalog -db PATH check <baseline.json>             CI gate: fail on regression/new drift

Ingest individual sources (normally driven by 'build'):
  kensa-catalog -db PATH ingest stig <os> <release> <xccdf-path>
  kensa-catalog -db PATH ingest cis  <cis_facts_<os>.json>
  kensa-catalog -db PATH ingest nist <nist_800-53_r5_controls.json>
  kensa-catalog -db PATH ingest cci  <cci_800-53_r5_edges.json>
  kensa-catalog -db PATH ingest coverage <corpus-coverage.json>
  kensa-catalog -db PATH ingest verifications <verifications.json>
`)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "kensa-catalog:", err)
	os.Exit(1)
}
