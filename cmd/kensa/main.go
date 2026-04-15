// Command kensa is the Kensa CLI — the primary operator interface for
// detecting capabilities, checking compliance, remediating rules,
// rolling back transactions, and querying the audit log.
//
// Usage:
//
//	kensa [--db path] <command> [flags]
//
// Commands:
//
//	detect      Probe a host and print its capability set.
//	check       Run read-only compliance checks (no apply).
//	remediate   Apply failing rules to a host.
//	rollback    Roll back a past transaction by ID.
//	history     Query the transaction log.
//	plan        Preview a rule transaction without executing.
//	coverage    List registered handler mechanisms.
//	version     Print version information.
//
// Global flags:
//
//	--db path   SQLite transaction-log path (default: .kensa/results.db).
//
// Run "kensa <command> --help" for subcommand flags.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/detect"
	"github.com/Hanalyx/kensa-go/internal/engine"
	"github.com/Hanalyx/kensa-go/internal/evidence"
	"github.com/Hanalyx/kensa-go/internal/handler"
	"github.com/Hanalyx/kensa-go/internal/rule"
	"github.com/Hanalyx/kensa-go/internal/scan"
	"github.com/Hanalyx/kensa-go/internal/transport/ssh"
	"github.com/Hanalyx/kensa-go/pkg/kensa"

	// Import all handler packages to trigger their init() registrations.
	_ "github.com/Hanalyx/kensa-go/internal/handlers/auditruleset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configsetdropin"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/cronjob"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/fileabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filecontent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filepermissions"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/kernelmoduledisable"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/mountoptionset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/packageabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/packagepresent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/pammoduleconfigure"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/selinuxbooleanset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/servicedisabled"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/serviceenabled"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/servicemasked"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/sysctlset"
)

func main() {
	dbPath := flag.String("db", "", "SQLite transaction-log path (default: .kensa/results.db)")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]
	ctx := context.Background()

	var err error
	switch cmd {
	case "detect":
		err = runDetect(ctx, args)
	case "check":
		err = runCheck(ctx, args)
	case "remediate":
		err = runRemediate(ctx, *dbPath, args)
	case "rollback":
		err = runRollback(ctx, *dbPath, args)
	case "history":
		err = runHistory(ctx, *dbPath, args)
	case "plan":
		err = runPlan(ctx, *dbPath, args)
	case "coverage":
		runCoverage()
	case "version":
		fmt.Println("kensa v0.1.0-dev (kensa-go)")
	default:
		fmt.Fprintf(os.Stderr, "kensa: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "kensa %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: kensa [--db path] <command> [flags]

Commands:
  detect      Probe a host and print its capability set
  check       Run read-only compliance checks (no apply)
  remediate   Apply failing rules to a host
  rollback    Roll back a past transaction by ID
  history     Query the transaction log
  plan        Preview a rule transaction without executing
  coverage    List registered handler mechanisms
  version     Print version information

Global flags:
  --db path   SQLite transaction-log path (default: .kensa/results.db)

Run "kensa <command> --help" for subcommand flags.
`)
}

// ─── detect ────────────────────────────────────────────────────────────────

// runDetect connects to a host and prints its capability set.
func runDetect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	host := fs.String("host", "", "target hostname (required)")
	user := fs.String("user", "", "SSH user (default: current user)")
	port := fs.Int("port", 22, "SSH port")
	keyPath := fs.String("key", "", "SSH private key path")
	sudo := fs.Bool("sudo", false, "wrap commands in sudo")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		fs.Usage()
		return errors.New("--host is required")
	}

	hostCfg := api.HostConfig{
		Hostname: *host,
		User:     *user,
		Port:     *port,
		KeyPath:  *keyPath,
		Sudo:     *sudo,
	}
	transport, err := ssh.Factory{}.Connect(ctx, hostCfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = transport.Close() }()

	caps, err := detect.Detect(ctx, transport)
	if err != nil {
		return fmt.Errorf("detect: %w", err)
	}

	switch *format {
	case "json":
		return printJSON(caps)
	default:
		printCapsTable(*host, caps)
	}
	return nil
}

func printCapsTable(hostID string, caps api.CapabilitySet) {
	names := make([]string, 0, len(caps))
	for k := range caps {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Printf("Capabilities for %s:\n", hostID)
	for _, name := range names {
		mark := "✗"
		if caps[name] {
			mark = "✓"
		}
		fmt.Printf("  %s  %s\n", mark, name)
	}
}

// ─── check ─────────────────────────────────────────────────────────────────

// runCheck loads rule files and runs read-only compliance checks.
func runCheck(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	host := fs.String("host", "", "target hostname (required)")
	user := fs.String("user", "", "SSH user")
	port := fs.Int("port", 22, "SSH port")
	keyPath := fs.String("key", "", "SSH private key path")
	sudo := fs.Bool("sudo", false, "wrap commands in sudo")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("--host is required")
	}
	if fs.NArg() == 0 {
		return errors.New("at least one rule YAML file is required")
	}

	rules, err := loadRules(fs.Args())
	if err != nil {
		return err
	}

	hostCfg := api.HostConfig{
		Hostname: *host, User: *user, Port: *port, KeyPath: *keyPath, Sudo: *sudo,
	}
	transport, err := ssh.Factory{}.Connect(ctx, hostCfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = transport.Close() }()

	runner := scan.New(nil)
	result, err := runner.Scan(ctx, transport, rules)
	if err != nil {
		return err
	}
	result.HostID = *host

	switch *format {
	case "json":
		return printJSON(result)
	default:
		printScanTable(*host, rules, result)
	}
	return nil
}

func printScanTable(hostID string, rules []*api.Rule, result *api.ScanResult) {
	pass, fail, errs := 0, 0, 0
	fmt.Printf("Check results for %s:\n\n", hostID)
	fmt.Printf("  %-40s  %-10s  %s\n", "RULE", "STATUS", "DETAIL")
	fmt.Println("  " + strings.Repeat("-", 80))
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		status := "PASS"
		switch txr.Status {
		case api.StatusErrored:
			status = "ERROR"
			errs++
		case api.StatusCommitted:
			pass++
		default:
			status = "FAIL"
			fail++
		}
		detail := ""
		if len(txr.Steps) > 0 {
			detail = truncate(txr.Steps[0].Detail, 50)
		}
		if txr.Error != nil {
			detail = truncate(txr.Error.Error(), 50)
		}
		fmt.Printf("  %-40s  %-10s  %s\n", truncate(ruleID, 40), status, detail)
	}
	fmt.Printf("\n  %d passed, %d failed, %d errors\n", pass, fail, errs)
}

// ─── remediate ─────────────────────────────────────────────────────────────

// runRemediate loads rule files and remediates failing rules.
func runRemediate(ctx context.Context, dbPath string, args []string) error {
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	host := fs.String("host", "", "target hostname (required)")
	user := fs.String("user", "", "SSH user")
	port := fs.Int("port", 22, "SSH port")
	keyPath := fs.String("key", "", "SSH private key path")
	sudo := fs.Bool("sudo", false, "wrap commands in sudo")
	format := fs.String("format", "table", "output format: table or json")
	oscalOut := fs.String("oscal", "", "write OSCAL Assessment Results to this file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("--host is required")
	}
	if fs.NArg() == 0 {
		return errors.New("at least one rule YAML file is required")
	}

	rules, err := loadRules(fs.Args())
	if err != nil {
		return err
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	hostCfg := api.HostConfig{
		Hostname: *host, User: *user, Port: *port, KeyPath: *keyPath, Sudo: *sudo,
	}
	result, err := svc.Remediate(ctx, hostCfg, rules)
	if err != nil {
		return err
	}

	switch *format {
	case "json":
		if err := printJSON(result); err != nil {
			return err
		}
	default:
		printRemediateTable(*host, rules, result)
	}

	// Optionally export OSCAL for each committed transaction.
	if *oscalOut != "" {
		if err := writeOSCALFile(*oscalOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "kensa remediate: OSCAL export: %v\n", err)
		}
	}
	return nil
}

func printRemediateTable(hostID string, rules []*api.Rule, result *api.RemediationResult) {
	committed, rolledBack, skipped, errs := 0, 0, 0, 0
	fmt.Printf("Remediation results for %s:\n\n", hostID)
	fmt.Printf("  %-40s  %-15s\n", "RULE", "STATUS")
	fmt.Println("  " + strings.Repeat("-", 60))
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		status := string(txr.Status)
		switch txr.Status {
		case api.StatusCommitted:
			committed++
		case api.StatusRolledBack:
			rolledBack++
		case api.StatusErrored:
			errs++
			if txr.Error != nil {
				status = "errored: " + truncate(txr.Error.Error(), 30)
			}
		default:
			skipped++
		}
		fmt.Printf("  %-40s  %-15s\n", truncate(ruleID, 40), status)
	}
	fmt.Printf("\n  %d committed, %d rolled_back, %d errors, %d skipped\n",
		committed, rolledBack, errs, skipped)
}

func writeOSCALFile(path string, result *api.RemediationResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for _, txr := range result.Transactions {
		if txr.Envelope == nil {
			continue
		}
		if err := evidence.WriteOSCAL(f, txr.Envelope); err != nil {
			return err
		}
	}
	return nil
}

// ─── rollback ──────────────────────────────────────────────────────────────

// runRollback rolls back a past transaction by ID.
func runRollback(ctx context.Context, dbPath string, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	host := fs.String("host", "", "target hostname (required)")
	user := fs.String("user", "", "SSH user")
	port := fs.Int("port", 22, "SSH port")
	keyPath := fs.String("key", "", "SSH private key path")
	sudo := fs.Bool("sudo", false, "wrap commands in sudo")
	txnIDStr := fs.String("txn", "", "transaction UUID to roll back (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("--host is required")
	}
	if *txnIDStr == "" {
		return errors.New("--txn is required")
	}
	txnID, err := uuid.Parse(*txnIDStr)
	if err != nil {
		return fmt.Errorf("invalid --txn UUID: %w", err)
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	hostCfg := api.HostConfig{
		Hostname: *host, User: *user, Port: *port, KeyPath: *keyPath, Sudo: *sudo,
	}
	result, err := svc.Rollback(ctx, hostCfg, txnID)
	if err != nil {
		return err
	}
	return printJSON(result)
}

// ─── history ───────────────────────────────────────────────────────────────

// runHistory queries the transaction log and prints results.
func runHistory(ctx context.Context, dbPath string, args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	hostID := fs.String("host", "", "filter by host ID")
	ruleID := fs.String("rule", "", "filter by rule ID")
	since := fs.String("since", "", "filter since duration (e.g. 24h) or RFC3339 time")
	limit := fs.Int("limit", 50, "maximum rows to return")
	format := fs.String("format", "table", "output format: table or json")
	txnIDStr := fs.String("txn", "", "get a single transaction by UUID")
	aggregate := fs.String("aggregate", "", "aggregate key: by_host, by_rule, by_framework_control")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	log := svc.TransactionLog()
	if log == nil {
		return errors.New("transaction log not available (store not wired)")
	}

	if *txnIDStr != "" {
		txnID, err := uuid.Parse(*txnIDStr)
		if err != nil {
			return fmt.Errorf("invalid --txn UUID: %w", err)
		}
		rec, err := log.Get(ctx, txnID)
		if err != nil {
			return fmt.Errorf("get transaction: %w", err)
		}
		return printJSON(rec)
	}

	filter := api.LogFilter{}
	if *hostID != "" {
		filter.HostIDs = []string{*hostID}
	}
	if *ruleID != "" {
		filter.RuleIDs = []string{*ruleID}
	}
	if *since != "" {
		t, err := parseSince(*since)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		filter.Since = t
	}

	if *aggregate != "" {
		aggResult, err := log.Aggregate(ctx, filter, api.AggregateKey(*aggregate))
		if err != nil {
			return fmt.Errorf("aggregate: %w", err)
		}
		return printJSON(aggResult)
	}

	result, err := log.Query(ctx, filter, api.Page{Limit: *limit})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	switch *format {
	case "json":
		return printJSON(result)
	default:
		printHistoryTable(result.Transactions)
		fmt.Printf("\n%d of %d transactions shown\n", len(result.Transactions), result.Total)
	}
	return nil
}

// ─── plan ──────────────────────────────────────────────────────────────────

// runPlan loads a rule and previews the transaction without executing.
func runPlan(ctx context.Context, dbPath string, args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	host := fs.String("host", "", "target hostname (required)")
	user := fs.String("user", "", "SSH user")
	port := fs.Int("port", 22, "SSH port")
	keyPath := fs.String("key", "", "SSH private key path")
	sudo := fs.Bool("sudo", false, "wrap commands in sudo")
	format := fs.String("format", "text", "output format: text, markdown, json, plain")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *host == "" {
		return errors.New("--host is required")
	}
	if fs.NArg() == 0 {
		return errors.New("a rule YAML file is required")
	}

	r, err := rule.ParseFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("parse rule: %w", err)
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	hostCfg := api.HostConfig{
		Hostname: *host, User: *user, Port: *port, KeyPath: *keyPath, Sudo: *sudo,
	}
	plan, err := svc.Plan(ctx, hostCfg, r)
	if err != nil {
		return err
	}

	out, err := engine.FormatPlan(plan, api.PreviewFormat(*format))
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// ─── coverage ──────────────────────────────────────────────────────────────

// runCoverage lists all registered handler mechanisms.
func runCoverage() {
	names := handler.Default().Names()
	sort.Strings(names)
	fmt.Printf("Registered mechanisms (%d):\n", len(names))
	for i, n := range names {
		h, _ := handler.Default().Get(n)
		capturable := "capturable"
		if !h.Capturable() {
			capturable = "non-capturable"
		}
		fmt.Printf("  %2d. %-30s  %s\n", i+1, n, capturable)
	}
}

// ─── helpers ───────────────────────────────────────────────────────────────

// loadRules parses a set of rule YAML files into []*api.Rule.
func loadRules(paths []string) ([]*api.Rule, error) {
	rules := make([]*api.Rule, 0, len(paths))
	for _, p := range paths {
		r, err := rule.ParseFile(p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// parseSince parses --since as either a duration (e.g. "24h") or an
// RFC3339 timestamp.
func parseSince(s string) (time.Time, error) {
	d, err := time.ParseDuration(s)
	if err == nil {
		return time.Now().Add(-d), nil
	}
	return time.Parse(time.RFC3339, s)
}

// printJSON encodes v to stdout as indented JSON.
func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printHistoryTable prints a compact tabular summary of transactions.
func printHistoryTable(txns []api.TransactionRecord) {
	fmt.Printf("%-36s  %-15s  %-25s  %-15s  %s\n",
		"TRANSACTION-ID", "STATUS", "RULE", "HOST", "FINISHED")
	fmt.Println(strings.Repeat("-", 105))
	for _, t := range txns {
		fmt.Printf("%-36s  %-15s  %-25s  %-15s  %s\n",
			t.ID,
			t.Status,
			truncate(t.RuleID, 25),
			truncate(t.HostID, 15),
			t.FinishedAt.Format(time.RFC3339),
		)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
