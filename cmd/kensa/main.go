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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

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
	_ "github.com/Hanalyx/kensa-go/internal/handlers/aptabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/aptpresent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/auditruleset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/authselectfeatureenable"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/commandexec"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configappend"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/configsetdropin"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/cronjob"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/cryptopolicyset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/cryptopolicysubpolicy"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/dconfset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/fileabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filecontent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filepermissions"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/grubparameterremove"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/grubparameterset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/kernelmoduledisable"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/manual"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/mountoptionset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/packageabsent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/packagepresent"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/pammodulearg"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/pammoduleconfigure"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/selinuxbooleanset"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/servicedisabled"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/serviceenabled"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/servicemasked"
	_ "github.com/Hanalyx/kensa-go/internal/handlers/sysctlset"
)

// version is the kensa-go binary version string surfaced by --version
// and the `version` subcommand. Bumped manually per release.
const version = "v0.1.0-dev"

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

// runCLI executes the kensa CLI against argv (typically os.Args[1:]) and
// returns the process exit code. Extracting this from main lets tests
// drive the parser end-to-end without spawning subprocesses.
//
// Exit code contract (deliverable C-001 in docs/roadmap/DELIVERABLES.md):
//
//	0  success, or --help / --version (informational request honored)
//	1  runtime error (subcommand failed, transport error, etc.)
//	2  usage error (bad flag, unknown subcommand, missing required arg)
//
// This contract follows GNU/POSIX convention. Documented in the manpage
// (forthcoming) and in `docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md` §2.
func runCLI(argv []string) int {
	// Backward-compat shim: stdlib `flag` accepted single-dash long forms
	// like `-db /path`, but pflag (GNU/POSIX strict) treats that as `-d -b`.
	// Rewrite the legacy form to `--db` with a deprecation warning so
	// existing scripts keep working through one minor release. Remove
	// this shim with the v0.2 cycle.
	argv = rewriteLegacyDb(argv)

	topFlags := pflag.NewFlagSet("kensa", pflag.ContinueOnError)
	// Stop parsing flags at the first positional (the subcommand name) so
	// subcommand-specific flags like `kensa check --host foo` aren't
	// interpreted as top-level flags.
	topFlags.SetInterspersed(false)
	topFlags.SortFlags = false
	// Suppress pflag's default usage-on-error; we want errors on stderr
	// and explicit-help text on stdout, which the auto-print can't
	// distinguish.
	topFlags.SetOutput(io.Discard)

	var (
		showHelp    bool
		showVersion bool
		dbPath      string
	)
	topFlags.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	topFlags.BoolVarP(&showVersion, "version", ShortVersion, false, "print version and exit")
	topFlags.StringVarP(&dbPath, "db", ShortDb, "", "SQLite transaction-log path (default: .kensa/results.db)")

	if err := topFlags.Parse(argv); err != nil {
		// pflag.ErrHelp shouldn't fire because we registered --help/-h
		// ourselves, but handle it defensively.
		if errors.Is(err, pflag.ErrHelp) {
			printUsage(os.Stdout)
			return 0
		}
		fmt.Fprintf(os.Stderr, "kensa: %v\n", err)
		fmt.Fprintln(os.Stderr, "Try 'kensa --help' for usage.")
		return 2
	}

	if showHelp {
		printUsage(os.Stdout)
		return 0
	}
	if showVersion {
		fmt.Printf("kensa %s (kensa-go)\n", version)
		return 0
	}

	if topFlags.NArg() == 0 {
		printUsage(os.Stderr)
		return 2
	}

	cmd := topFlags.Arg(0)
	args := topFlags.Args()[1:]
	ctx := context.Background()

	var err error
	switch cmd {
	case "detect":
		err = runDetect(ctx, args)
	case "check":
		err = runCheck(ctx, args)
	case "remediate":
		err = runRemediate(ctx, dbPath, args)
	case "rollback":
		err = runRollback(ctx, dbPath, args)
	case "history":
		err = runHistory(ctx, dbPath, args)
	case "plan":
		err = runPlan(ctx, dbPath, args)
	case "coverage":
		err = runCoverage(args)
	case "version":
		err = runVersion(args)
	default:
		fmt.Fprintf(os.Stderr, "kensa: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		return 2
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "kensa %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

// rewriteLegacyDb converts stdlib-flag-style single-dash `-db ...` and
// `-db=...` to pflag's `--db ...` and `--db=...`. Emits a deprecation
// warning to stderr so users see they need to migrate the syntax.
// Scope is intentionally narrow: only -db (the only top-level long flag
// that previously worked with single dash). Subcommand-level legacy
// flags will be handled by their own backward-compat shims as they
// migrate to pflag (deliverables C-002..C-004).
func rewriteLegacyDb(argv []string) []string {
	out := make([]string, 0, len(argv))
	warned := false
	for _, a := range argv {
		switch {
		case a == "-db":
			if !warned {
				fmt.Fprintln(os.Stderr, "kensa: warning: '-db' is deprecated; use '--db' or '-D' (the legacy form will be removed in v0.2)")
				warned = true
			}
			out = append(out, "--db")
		case strings.HasPrefix(a, "-db="):
			if !warned {
				fmt.Fprintln(os.Stderr, "kensa: warning: '-db=' is deprecated; use '--db=' or '-D=' (the legacy form will be removed in v0.2)")
				warned = true
			}
			out = append(out, "--db="+a[len("-db="):])
		default:
			out = append(out, a)
		}
	}
	return out
}

// rewriteLegacyLongForm converts stdlib-flag-style single-dash long forms
// (e.g., `-host foo`, `-host=foo`) to pflag's double-dash form
// (`--host foo`, `--host=foo`). Each subcommand passes the set of long
// flag names it accepts; only those names are rewritten so that real
// short forms (`-h`, `-H`, `-u`, etc.) are left untouched.
//
// One stderr deprecation warning per call. Removed in v0.2.
func rewriteLegacyLongForm(args []string, longNames map[string]bool) []string {
	out := make([]string, 0, len(args))
	warned := false
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
			out = append(out, a)
			continue
		}
		// `a` is single-dash. Extract the name (before any `=`).
		name := a[1:]
		if eq := strings.Index(name, "="); eq != -1 {
			name = name[:eq]
		}
		// Only rewrite multi-character names that match a known long flag.
		// Single-character names (e.g., `-h`) are real short forms.
		if len(name) > 1 && longNames[name] {
			if !warned {
				fmt.Fprintln(os.Stderr, "kensa: warning: stdlib-style single-dash long flags are deprecated; use --"+name+" (will be removed in v0.2)")
				warned = true
			}
			out = append(out, "-"+a) // prepend `-` to make double-dash
			continue
		}
		out = append(out, a)
	}
	return out
}

// printUsage writes the top-level help to w. Per GNU convention, --help
// goes to stdout and usage errors go to stderr — the caller chooses the
// writer accordingly.
func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: kensa [global flags] <command> [flags]

Commands:
  detect      Probe a host and print its capability set
  check       Run read-only compliance checks (no apply)
  remediate   Apply failing rules to a host
  rollback    Roll back a past transaction by ID
  history     Query the transaction log
  plan        Preview a rule transaction without executing
  coverage    List registered handler mechanisms

Global flags:
  -h, --help        Show this help and exit
  -V, --version     Print version and exit
  -D, --db PATH     SQLite transaction-log path (default: .kensa/results.db)

Run "kensa <command> --help" for subcommand flags.

Exit codes:
  0  success (or --help / --version)
  1  runtime error
  2  usage error (bad flag, unknown subcommand, missing required arg)
`)
}

// ─── detect ────────────────────────────────────────────────────────────────

// runDetect connects to a host and prints its capability set.
//
// Flag style follows the GNU/POSIX-strict short-letter table per
// docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §4. Short forms:
//
//	-H, --host       target hostname (capital H — `-h` is reserved for --help)
//	-u, --user       SSH username
//	-p, --port       SSH port
//	-k, --key        SSH private key path (note: `-i` is reserved system-
//	                 wide for `--inventory` in `kensa check`, even though
//	                 `kensa detect` has no inventory flag — so `-k` is
//	                 used here for cross-subcommand consistency, deviating
//	                 from OpenSSH's `-i identity_file` idiom)
//	-s, --sudo       wrap commands in sudo
//	-f, --format     output format
//	-h, --help       show help
//
// Single-dash long forms (`-host`, `-user`, etc.) from the stdlib-flag
// era continue to parse via rewriteLegacyLongForm with a deprecation
// warning. Removed in v0.2.
func runDetect(ctx context.Context, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true,
		"key": true, "sudo": true, "format": true,
	})

	fs := pflag.NewFlagSet("detect", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		host     string
		user     string
		port     int
		keyPath  string
		sudo     bool
		format   string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table or json")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printDetectUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa detect --help'", err)
	}
	if showHelp {
		printDetectUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printDetectUsage(os.Stderr, fs)
		return errors.New("--host is required")
	}

	hostCfg := api.HostConfig{
		Hostname: host,
		User:     user,
		Port:     port,
		KeyPath:  keyPath,
		Sudo:     sudo,
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

	switch format {
	case "json":
		return printJSON(caps)
	default:
		printCapsTable(host, caps)
	}
	return nil
}

// printDetectUsage writes the `kensa detect` help text to w. Per GNU
// convention, --help goes to stdout; usage errors go to stderr.
func printDetectUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa detect [flags]

Probe a host and print its capability set. Read-only; no mutations.

Flags:
%s
Examples:
  kensa detect -H 192.168.1.211 -u owadmin -s
  kensa detect --host web-01 --user admin --format json
`, fs.FlagUsages())
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
//
// Flag style: GNU/POSIX-strict per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md
// §4.2 short-letter table:
//
//	-H, --host          target hostname
//	-u, --user          SSH username
//	-p, --port          SSH port
//	-k, --key           SSH private key path
//	-s, --sudo          wrap in sudo
//	-f, --format        output format
//	-r, --rules-dir     rules directory
//	    --inventory     Ansible-style inventory (no short — `-i` reserved
//	                    elsewhere is debatable, but no other subcommand
//	                    in kensa uses --inventory, so leaving it long-only
//	                    keeps the system-wide table consistent)
//	-h, --help          show help
//
// Single-dash long forms (`-host`, `-rules-dir`, etc.) from the stdlib-
// flag era continue to parse via rewriteLegacyLongForm with a deprecation
// warning. Removed in v0.2.
func runCheck(ctx context.Context, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true, "key": true,
		"sudo": true, "format": true, "rules-dir": true, "inventory": true,
	})

	fs := pflag.NewFlagSet("check", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp  bool
		host      string
		user      string
		port      int
		keyPath   string
		sudo      bool
		format    string
		rulesDir  string
		inventory string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required if no --inventory)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table, json, or jsonl")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory to scan for *.yml rule files")
	fs.StringVar(&inventory, "inventory", "", "Ansible-style inventory.ini for multi-host check (long-only)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printCheckUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa check --help'", err)
	}
	if showHelp {
		printCheckUsage(os.Stdout, fs)
		return nil
	}

	rules, err := loadRulesFromDirOrFiles(rulesDir, fs.Args())
	if err != nil {
		return err
	}

	if inventory != "" {
		return runCheckInventory(ctx, inventory, user, port, keyPath, sudo, format, rules)
	}
	if host == "" {
		printCheckUsage(os.Stderr, fs)
		return errors.New("--host or --inventory is required")
	}

	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath, Sudo: sudo,
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
	result.HostID = host

	switch format {
	case "json":
		return printJSON(result)
	case "jsonl":
		return printJSONL(rules, result)
	default:
		printScanTable(host, rules, result)
	}
	return nil
}

// printCheckUsage writes the `kensa check` help text. --help to stdout,
// usage errors to stderr per GNU.
func printCheckUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa check [flags] [rule.yml ...]

Run read-only compliance checks against one host or an inventory.

Flags:
%s
Examples:
  kensa check -H 192.168.1.211 -u owadmin -s -r /path/to/rules
  kensa check --inventory hosts.ini --sudo --rules-dir /path/to/rules
  kensa check -H web-01 -u admin -s --format jsonl rule1.yml rule2.yml
`, fs.FlagUsages())
}

// runCheckInventory fans out a check across all hosts in an inventory file.
func runCheckInventory(ctx context.Context, inventoryPath, user string, port int, keyPath string, sudo bool, format string, rules []*api.Rule) error {
	hosts, err := parseInventory(inventoryPath)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}

	type hostResult struct {
		host   inventoryHost
		result *api.ScanResult
		err    error
	}

	results := make([]hostResult, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(idx int, ih inventoryHost) {
			defer wg.Done()
			u := ih.user
			if user != "" {
				u = user
			}
			p := port
			if ih.port != 0 {
				p = ih.port
			}
			hostCfg := api.HostConfig{
				Hostname: ih.addr, User: u, Port: p, KeyPath: keyPath, Sudo: sudo,
			}
			transport, err := ssh.Factory{}.Connect(ctx, hostCfg)
			if err != nil {
				results[idx] = hostResult{host: ih, err: fmt.Errorf("connect: %w", err)}
				return
			}
			defer func() { _ = transport.Close() }()
			runner := scan.New(nil)
			res, err := runner.Scan(ctx, transport, rules)
			if err != nil {
				results[idx] = hostResult{host: ih, err: err}
				return
			}
			res.HostID = ih.addr
			results[idx] = hostResult{host: ih, result: res}
		}(i, h)
	}
	wg.Wait()

	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", r.host.addr, r.err)
			continue
		}
		switch format {
		case "json":
			if err := printJSON(r.result); err != nil {
				return err
			}
		case "jsonl":
			if err := printJSONL(rules, r.result); err != nil {
				return err
			}
		default:
			printScanTable(r.host.addr, rules, r.result)
		}
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
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true, "key": true,
		"sudo": true, "format": true, "oscal": true, "rules-dir": true,
	})

	fs := pflag.NewFlagSet("remediate", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		host     string
		user     string
		port     int
		keyPath  string
		sudo     bool
		format   string
		oscalOut string
		rulesDir string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table or json")
	fs.StringVar(&oscalOut, "oscal", "", "write OSCAL Assessment Results to this file (long-only)")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory to scan for *.yml rule files")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printRemediateUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa remediate --help'", err)
	}
	if showHelp {
		printRemediateUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printRemediateUsage(os.Stderr, fs)
		return errors.New("--host is required")
	}

	rules, err := loadRulesFromDirOrFiles(rulesDir, fs.Args())
	if err != nil {
		return err
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath, Sudo: sudo,
	}
	result, err := svc.Remediate(ctx, hostCfg, rules)
	if err != nil {
		return err
	}

	switch format {
	case "json":
		if err := printJSON(result); err != nil {
			return err
		}
	default:
		printRemediateTable(host, rules, result)
	}

	// Optionally export OSCAL for each committed transaction.
	if oscalOut != "" {
		if err := writeOSCALFile(oscalOut, result); err != nil {
			fmt.Fprintf(os.Stderr, "kensa remediate: OSCAL export: %v\n", err)
		}
	}
	return nil
}

// printRemediateUsage writes the `kensa remediate` help text to w.
func printRemediateUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa remediate [flags] [rule.yml ...]

Apply failing rules to a host. Each rule runs as a four-phase
atomic transaction; on validation failure, the engine rolls back
to captured pre-state.

Flags:
%s
Examples:
  kensa remediate -H 192.168.1.211 -u owadmin -s -r /path/to/rules
  kensa remediate -H web-01 -u admin -s --format json --oscal /tmp/results.oscal.json
`, fs.FlagUsages())
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
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true, "key": true,
		"sudo": true, "txn": true,
	})

	fs := pflag.NewFlagSet("rollback", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		host     string
		user     string
		port     int
		keyPath  string
		sudo     bool
		txnIDStr string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&txnIDStr, "txn", ShortTransaction, "", "transaction UUID to roll back (required)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printRollbackUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa rollback --help'", err)
	}
	if showHelp {
		printRollbackUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printRollbackUsage(os.Stderr, fs)
		return errors.New("--host is required")
	}
	if txnIDStr == "" {
		printRollbackUsage(os.Stderr, fs)
		return errors.New("--txn is required")
	}
	txnID, err := uuid.Parse(txnIDStr)
	if err != nil {
		return fmt.Errorf("invalid --txn UUID: %w", err)
	}

	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath, Sudo: sudo,
	}
	result, err := svc.Rollback(ctx, hostCfg, txnID)
	if err != nil {
		return err
	}
	return printJSON(result)
}

// printRollbackUsage writes the `kensa rollback` help text to w.
func printRollbackUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa rollback [flags]

Roll back a past transaction by ID using captured pre-state.

Flags:
%s
Example:
  kensa rollback -H 192.168.1.211 -u owadmin -s -t 8c3a1e2b-...
`, fs.FlagUsages())
}

// ─── history ───────────────────────────────────────────────────────────────

// runHistory queries the transaction log and prints results.
func runHistory(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "rule": true, "since": true, "limit": true,
		"format": true, "txn": true, "aggregate": true,
	})

	fs := pflag.NewFlagSet("history", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp  bool
		hostID    string
		ruleID    string
		since     string
		limit     int
		format    string
		txnIDStr  string
		aggregate string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&hostID, "host", ShortHost, "", "filter by host ID")
	fs.StringVarP(&ruleID, "rule", ShortRule, "", "filter by rule ID")
	fs.StringVarP(&since, "since", ShortSince, "", "filter since duration (e.g. 24h) or RFC3339 time")
	fs.IntVarP(&limit, "limit", ShortLimit, 50, "maximum rows to return")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table or json")
	fs.StringVarP(&txnIDStr, "txn", ShortTransaction, "", "get a single transaction by UUID")
	fs.StringVarP(&aggregate, "aggregate", ShortAggregate, "", "aggregate key: by_host, by_rule, by_framework_control")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printHistoryUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa history --help'", err)
	}
	if showHelp {
		printHistoryUsage(os.Stdout, fs)
		return nil
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

	if txnIDStr != "" {
		txnID, err := uuid.Parse(txnIDStr)
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
	if hostID != "" {
		filter.HostIDs = []string{hostID}
	}
	if ruleID != "" {
		filter.RuleIDs = []string{ruleID}
	}
	if since != "" {
		t, err := parseSince(since)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		filter.Since = t
	}

	if aggregate != "" {
		aggResult, err := log.Aggregate(ctx, filter, api.AggregateKey(aggregate))
		if err != nil {
			return fmt.Errorf("aggregate: %w", err)
		}
		return printJSON(aggResult)
	}

	result, err := log.Query(ctx, filter, api.Page{Limit: limit})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	switch format {
	case "json":
		return printJSON(result)
	default:
		printHistoryTable(result.Transactions)
		fmt.Printf("\n%d of %d transactions shown\n", len(result.Transactions), result.Total)
	}
	return nil
}

// printHistoryUsage writes the `kensa history` help text to w.
func printHistoryUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa history [flags]

Query the transaction log. Without filters, lists recent transactions.

Flags:
%s
Examples:
  kensa history                                  # 50 most recent
  kensa history -n 200 --format json             # last 200 as JSON
  kensa history -H 192.168.1.211 -S 24h          # one host, last 24h
  kensa history -t 8c3a1e2b-...                  # one transaction by UUID
  kensa history -a by_host -S 7d                 # 7-day posture per host
`, fs.FlagUsages())
}

// ─── plan ──────────────────────────────────────────────────────────────────

// runPlan loads a rule and previews the transaction without executing.
func runPlan(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true, "key": true,
		"sudo": true, "format": true,
	})

	fs := pflag.NewFlagSet("plan", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		host     string
		user     string
		port     int
		keyPath  string
		sudo     bool
		format   string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text, markdown, json, plain")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printPlanUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa plan --help'", err)
	}
	if showHelp {
		printPlanUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printPlanUsage(os.Stderr, fs)
		return errors.New("--host is required")
	}
	if fs.NArg() == 0 {
		printPlanUsage(os.Stderr, fs)
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
		Hostname: host, User: user, Port: port, KeyPath: keyPath, Sudo: sudo,
	}
	plan, err := svc.Plan(ctx, hostCfg, r)
	if err != nil {
		return err
	}

	out, err := engine.FormatPlan(plan, api.PreviewFormat(format))
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// printPlanUsage writes the `kensa plan` help text to w.
func printPlanUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa plan [flags] rule.yml

Preview a rule transaction without executing it. Returns a structured
Plan with captured pre-state, apply steps, validators, rollback plan,
and warnings.

Flags:
%s
Example:
  kensa plan -H 192.168.1.211 -u owadmin -s -f markdown rule.yml
`, fs.FlagUsages())
}

// ─── coverage ──────────────────────────────────────────────────────────────

// runCoverage lists all registered handler mechanisms.
//
// Note: this subcommand will be renamed to `kensa mechanisms` in CLI
// Phase 4 (per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §5.11) so that
// `kensa coverage` can be repurposed for framework coverage reporting
// (Python kensa's `coverage` semantics). Until then, accepts only
// `--help`/`-h` for parity with the rest of the CLI.
func runCoverage(args []string) error {
	fs := pflag.NewFlagSet("coverage", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var showHelp bool
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printCoverageUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa coverage --help'", err)
	}
	if showHelp {
		printCoverageUsage(os.Stdout, fs)
		return nil
	}

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
	return nil
}

// runVersion prints the kensa version. Subcommand form kept for
// backward compatibility; the canonical GNU/POSIX form is `kensa
// --version`. Honors `--help`/`-h` for parity with other subcommands.
//
// Planned removal: v0.2 (per docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md
// §5.12). After removal, only the top-level `--version` flag will print
// the version string.
func runVersion(args []string) error {
	fs := pflag.NewFlagSet("version", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var showHelp bool
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printVersionUsage(os.Stdout, fs)
			return nil
		}
		return fmt.Errorf("%w; try 'kensa version --help'", err)
	}
	if showHelp {
		printVersionUsage(os.Stdout, fs)
		return nil
	}

	fmt.Printf("kensa %s (kensa-go)\n", version)
	return nil
}

// printVersionUsage writes the `kensa version` help text to w.
func printVersionUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa version

Print the kensa-go binary version. The top-level '--version' flag is
the canonical GNU/POSIX form; this subcommand is preserved for
backward compatibility and is planned for removal in v0.2.

Flags:
%s`, fs.FlagUsages())
}

// printCoverageUsage writes the `kensa coverage` help text to w.
func printCoverageUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa coverage [flags]

List every handler mechanism registered with the kensa-go engine,
marked capturable (participates in atomic transactions) or
non-capturable (transactional: false escape hatch).

Flags:
%s
Example:
  kensa coverage
`, fs.FlagUsages())
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

// loadRulesFromDirOrFiles loads rules from a directory (if dir != "") or
// from the explicit file paths. Returns an error when both are empty.
func loadRulesFromDirOrFiles(dir string, paths []string) ([]*api.Rule, error) {
	if dir != "" {
		var found []string
		if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".yml") {
				found = append(found, path)
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("walk %s: %w", dir, err)
		}
		if len(found) == 0 {
			return nil, fmt.Errorf("no *.yml files found in %s", dir)
		}
		return loadRulesSkipInvalid(found)
	}
	if len(paths) == 0 {
		return nil, errors.New("at least one rule YAML file or -rules-dir is required")
	}
	return loadRules(paths)
}

// loadRulesSkipInvalid loads rules, printing a warning and skipping files
// that fail to parse rather than aborting the whole load.
func loadRulesSkipInvalid(paths []string) ([]*api.Rule, error) {
	rules := make([]*api.Rule, 0, len(paths))
	for _, p := range paths {
		r, err := rule.ParseFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skip %s: %v\n", p, err)
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// inventoryHost is a single entry from a parsed inventory file.
type inventoryHost struct {
	addr string
	user string
	port int
}

// parseInventory reads an Ansible-style INI inventory file and returns
// all host entries. Lines starting with '#' or '[' (group headers) are
// skipped. Host lines have the form:
//
//	<addr>  [ansible_user=<user>]  [ansible_port=<port>]
func parseInventory(path string) ([]inventoryHost, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []inventoryHost
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		fields := strings.Fields(line)
		h := inventoryHost{addr: fields[0]}
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "ansible_user=") {
				h.user = strings.TrimPrefix(f, "ansible_user=")
			}
			if strings.HasPrefix(f, "ansible_port=") {
				_, _ = fmt.Sscanf(strings.TrimPrefix(f, "ansible_port="), "%d", &h.port)
			}
		}
		hosts = append(hosts, h)
	}
	return hosts, scanner.Err()
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

// scanLine is the JSON Lines wire shape consumed by OpenWatch's ingestion
// pipeline. One line per host per scan run; compact (no internal newlines)
// so OpenWatch can stream-parse with jq or its own NDJSON reader.
type scanLine struct {
	ScannedAt  time.Time          `json:"scanned_at"`
	HostID     string             `json:"host_id"`
	Passed     int                `json:"passed"`
	Failed     int                `json:"failed"`
	Errors     int                `json:"errors"`
	Rules      []scanLineRule     `json:"rules"`
}

type scanLineRule struct {
	RuleID string `json:"rule_id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// printJSONL encodes result as a single compact JSON line (NDJSON) to stdout.
// Each call emits exactly one newline-terminated JSON object — suitable for
// appending to a file or piping to OpenWatch's ingest endpoint.
// rules is indexed in parallel with result.Transactions to supply rule IDs
// (the scan result does not embed them).
func printJSONL(rules []*api.Rule, result *api.ScanResult) error {
	line := scanLine{
		ScannedAt: time.Now().UTC(),
		HostID:    result.HostID,
		Rules:     make([]scanLineRule, 0, len(result.Transactions)),
	}
	for i, txr := range result.Transactions {
		ruleID := ""
		if i < len(rules) {
			ruleID = rules[i].ID
		}
		r := scanLineRule{RuleID: ruleID}
		switch txr.Status {
		case api.StatusCommitted:
			r.Status = "pass"
			line.Passed++
		case api.StatusErrored:
			r.Status = "error"
			line.Errors++
			if txr.Error != nil {
				r.Detail = txr.Error.Error()
			}
		default:
			r.Status = "fail"
			line.Failed++
		}
		if r.Detail == "" && len(txr.Steps) > 0 {
			r.Detail = txr.Steps[0].Detail
		}
		line.Rules = append(line.Rules, r)
	}
	return json.NewEncoder(os.Stdout).Encode(line)
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
