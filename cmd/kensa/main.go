// Command kensa is the Kensa CLI — the primary operator interface for
// running, auditing, and rolling back Kensa transactions.
//
// Usage:
//
//	kensa [--db path] <command> [flags]
//
// Commands:
//
//	scan        [NOT YET IMPLEMENTED] Check host compliance without applying.
//	remediate   [NOT YET IMPLEMENTED] Apply failing rules to a host.
//	rollback    [NOT YET IMPLEMENTED] Rollback a past transaction by ID.
//	history     Query the transaction log.
//	coverage    List registered handler mechanisms.
//
// Global flags:
//
//	--db path   SQLite transaction-log path (default: .kensa/results.db).
//
// Subcommand flags are documented via each subcommand's --help flag.
//
// Design notes:
//
//   - scan, remediate, and rollback require the rule parser (Week 21).
//     They return ErrNotYetImplemented and print a helpful message so
//     operators know the feature is coming.
//   - history and coverage work today against the wired store and the
//     global handler registry.
//   - The DB path is passed as the first argument to pkg/kensa.Default()
//     so the same SQLite file is used by both the CLI and any daemon that
//     also writes to it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/handler"
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
	// Global flag: --db overrides the SQLite path.
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

	switch cmd {
	case "scan":
		runNotYetImplemented("scan", "rule parser (Week 21)")
	case "remediate":
		runNotYetImplemented("remediate", "rule parser (Week 21)")
	case "rollback":
		runNotYetImplemented("rollback", "rule parser (Week 21)")
	case "history":
		if err := runHistory(ctx, *dbPath, args); err != nil {
			fmt.Fprintf(os.Stderr, "kensa history: %v\n", err)
			os.Exit(1)
		}
	case "coverage":
		runCoverage()
	case "version":
		fmt.Println("kensa v0.1.0-dev (kensa-go)")
	default:
		fmt.Fprintf(os.Stderr, "kensa: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: kensa [--db path] <command> [flags]

Commands:
  scan        [pending Week 21] Check host compliance without applying
  remediate   [pending Week 21] Apply failing rules to a host
  rollback    [pending Week 21] Rollback a past transaction by ID
  history     Query the transaction log
  coverage    List registered handler mechanisms
  version     Print version information

Global flags:
  --db path   SQLite transaction-log path (default: .kensa/results.db)

Run "kensa <command> --help" for subcommand flags.
`)
}

// runNotYetImplemented prints a friendly pending-milestone message and exits 0.
func runNotYetImplemented(cmd, milestone string) {
	fmt.Printf("kensa %s: not yet implemented — depends on %s\n", cmd, milestone)
	fmt.Printf("Tracking: docs/KENSA_GO_DAY1_PLAN.md §11.5\n")
}

// ─── history subcommand ────────────────────────────────────────────────────

// runHistory queries the transaction log and prints results as JSON lines.
func runHistory(ctx context.Context, dbPath string, args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	hostID := fs.String("host", "", "filter by host ID")
	ruleID := fs.String("rule", "", "filter by rule ID")
	since := fs.String("since", "", "filter since duration (e.g. 24h) or RFC3339 time")
	limit := fs.Int("limit", 50, "maximum rows to return")
	format := fs.String("format", "json", "output format: json or table")
	txnIDStr := fs.String("txn", "", "get a single transaction by UUID")

	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer svc.Close()

	log := svc.TransactionLog()
	if log == nil {
		return errors.New("transaction log not available (store not wired)")
	}

	// Single-transaction get.
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

	// Build filter.
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

	result, err := log.Query(ctx, filter, api.Page{Limit: *limit})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	switch *format {
	case "table":
		printTable(result.Transactions)
	default:
		return printJSON(result)
	}
	return nil
}

// parseSince parses a --since value as either a duration (e.g. "24h") or
// an RFC3339 timestamp.
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

// printTable prints a compact tabular summary of transactions.
func printTable(txns []api.TransactionRecord) {
	fmt.Printf("%-36s  %-12s  %-20s  %-12s  %s\n",
		"TRANSACTION-ID", "STATUS", "RULE", "HOST", "FINISHED")
	fmt.Println(repeatStr("-", 100))
	for _, t := range txns {
		fmt.Printf("%-36s  %-12s  %-20s  %-12s  %s\n",
			t.ID,
			t.Status,
			truncate(t.RuleID, 20),
			truncate(t.HostID, 12),
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

func repeatStr(s string, n int) string {
	out := make([]byte, n*len(s))
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}

// ─── coverage subcommand ───────────────────────────────────────────────────

// runCoverage lists all registered handler mechanisms to stdout.
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
