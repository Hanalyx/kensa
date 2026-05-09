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
	"github.com/Hanalyx/kensa-go/internal/handler"
	"github.com/Hanalyx/kensa-go/internal/output"
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
		// UsageError → exit 2 (GNU/POSIX: invocation was wrong).
		// Anything else → exit 1 (something went wrong doing what
		// you asked). pflag.ErrHelp is handled separately and would
		// have returned 0 before reaching here.
		if IsUsageError(err) {
			return 2
		}
		return 1
	}
	return 0
}

// warnDeprecatedFlag emits a one-line deprecation warning to stderr
// when fs.Changed(name) reports that the operator explicitly set the
// flag (as opposed to the default firing). The warning text:
// "kensa: warning: --<name> is deprecated; use <replacement>
// (will be removed in v0.2)". Format and v0.2 marker match the
// pre-existing legacy-flag warnings (rewriteLegacyDb,
// rewriteLegacyLongForm) so operators see a consistent migration
// signal across the deprecation cycle.
//
// Per C-020, deprecation warnings always go to stderr regardless of
// --quiet. --quiet silences stdout body output; deprecation warnings
// are diagnostic information operators must see during the
// deprecation window, otherwise scripts using deprecated flags
// silently survive the cycle and break at removal time.
//
// Env-var opt-out: KENSA_NO_DEPRECATION_WARNINGS=1 silences these
// warnings for the current process. Intended for operators who have
// planned the migration but can't migrate immediately (e.g., a CI
// pipeline pinned to a specific release window). NOT a substitute
// for migrating — the underlying flags will be removed in v0.2
// regardless of whether the warning was visible.
//
// Note on explicit-default values: `--format table` (the default
// value, but explicitly typed on argv) triggers the warning. This
// is intentional — the FLAG itself is deprecated regardless of
// value. Suppressing on default-value-equality would create a
// foot-gun where one specific value of a deprecated flag silently
// outlives the deprecation window.
func warnDeprecatedFlag(fs *pflag.FlagSet, name, replacement string) {
	if !fs.Changed(name) {
		return
	}
	if os.Getenv("KENSA_NO_DEPRECATION_WARNINGS") == "1" {
		return
	}
	fmt.Fprintf(os.Stderr,
		"kensa: warning: --%s is deprecated; use %s (will be removed in v0.2)\n",
		name, replacement)
}

// routeFanOutError routes a FanOut return value through the right
// kensa-CLI exit-code lane. ErrUnsupportedFormat means the operator
// asked for a format that has no writer for the payload type
// (e.g., `kensa check -o oscal:foo` where oscal is registered for
// remediation only). That's a usage error (exit 2) per spec
// fanout C-07; non-format errors are runtime errors (exit 1).
//
// Without this routing, the FanOut error returns directly which
// the dispatcher classifies as a runtime error — operators with
// scripts that branch on exit code 1 vs 2 would see the wrong
// classification.
func routeFanOutError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, output.ErrUnsupportedFormat) {
		return WrapUsageError("--output", err)
	}
	return err
}

// resolveAndPrintIssues is the canonical pre-scan helper. Resolves
// the rule list (orders by depends_on, applies supersedes auto-
// resolution, detects conflicts and cycles) and emits the
// resolution summary to stderr.
//
// info: lines (supersedes notices) are suppressed when quiet is
// true so CI scripts running --quiet don't drown in cosmetic
// chatter. error: (cycles, dropped rules) and warning: (conflicts)
// lines always emit — operators must see real configuration
// problems regardless of --quiet.
func resolveAndPrintIssues(rules []*api.Rule, quiet bool) *rule.ResolvedRules {
	resolved := rule.Resolve(rules)
	for _, msg := range rule.FormatIssues(resolved) {
		if quiet && rule.IssueSeverity(msg) == "info" {
			continue
		}
		fmt.Fprintln(os.Stderr, "kensa: "+msg)
	}
	return resolved
}

// bodyOut returns the io.Writer to which a subcommand's default
// human-readable result body should be written. When the operator
// passes --quiet (-q), returns io.Discard so no body bytes hit
// stdout. Errors and warnings continue to use os.Stderr; --quiet
// does NOT silence them. Help and version output also bypass this
// helper and go directly to os.Stdout.
//
// Operators use --quiet in CI scripts where only the exit code
// matters (e.g., kensa check --quiet && deploy.sh). Once C-019's
// `-o FORMAT:PATH` mechanism lands, --quiet pairs naturally with
// it: file output proceeds, stdout stays clean.
func bodyOut(quiet bool) io.Writer {
	if quiet {
		return io.Discard
	}
	return os.Stdout
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
		quiet    bool
		outputs  []string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table or json (deprecated; use --output)")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")
	fs.StringSliceVarP(&outputs, "output", ShortOutput, nil, "output destination FORMAT[:PATH], repeatable (e.g., -o json -o csv:results.csv)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printDetectUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa detect --help'", err)
	}
	if showHelp {
		printDetectUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printDetectUsage(os.Stderr, fs)
		return NewUsageError("--host is required")
	}
	warnDeprecatedFlag(fs, "format", "--output FORMAT[:PATH]")

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

	if len(outputs) > 0 {
		specs, err := output.ParseAll(outputs)
		if err != nil {
			return WrapUsageError("--output", err)
		}
		return routeFanOutError(output.FanOutCaps(specs, bodyOut(quiet), host, caps))
	}
	return output.CapsWriterOrText(format).WriteCaps(bodyOut(quiet), host, caps)
}

// printDetectUsage writes the `kensa detect` help text to w. Per GNU
// convention, --help goes to stdout; usage errors go to stderr.
func printDetectUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa detect [flags]

Probe a host and print its capability set. Read-only; no mutations.

Flags:
%s
Examples:
  kensa detect -H 192.168.1.211 -u owadmin --sudo
  kensa detect --host web-01 --user admin --format json
`, fs.FlagUsages())
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
//	-i, --inventory     Ansible-style inventory.ini (C-023)
//	-v, --verbose       expand the compacted PASSED list (C-023)
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
		limit     string
		quiet     bool
		verbose   bool
		outputs   []string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required if no --inventory)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table, json, or jsonl (deprecated; use --output)")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory to scan for *.yml rule files")
	fs.StringVarP(&inventory, "inventory", ShortInventory, "", "Ansible-style inventory.ini for multi-host check")
	fs.StringVarP(&limit, "limit", ShortLimitGlob, "", "limit inventory hosts to glob/group pattern (ansible --limit semantics)")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")
	fs.BoolVarP(&verbose, "verbose", ShortVerbose, false, "expand the compacted PASSED list (text format only)")
	fs.StringSliceVarP(&outputs, "output", ShortOutput, nil, "output destination FORMAT[:PATH], repeatable")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printCheckUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa check --help'", err)
	}
	if showHelp {
		printCheckUsage(os.Stdout, fs)
		return nil
	}
	warnDeprecatedFlag(fs, "format", "--output FORMAT[:PATH]")

	// Validate flag-only constraints up front so usage errors don't
	// trail behind runtime work like rule loading or SSH dialing.
	// BLOCKING fix per peer review: --inventory + -o FORMAT:PATH
	// would call os.Create per host, truncating the file each
	// time and silently losing prior hosts' data. Reject the
	// combination loudly and point operators at the workaround.
	// (Streaming wrappers wired through fan-out is post-C-019.)
	if inventory != "" && len(outputs) > 0 {
		specs, perr := output.ParseAll(outputs)
		if perr != nil {
			return WrapUsageError("--output", perr)
		}
		for _, s := range specs {
			if s.Path != "" {
				return NewUsageError(fmt.Sprintf(
					"--inventory + --output %s: file outputs not yet supported in inventory mode "+
						"(would overwrite the file per-host with silent data loss). Use one path "+
						"per host (run kensa check per-host), omit Path to write to stdout, or "+
						"wait for streaming-writer integration.", s.String()))
			}
		}
	}

	rules, err := loadRulesFromDirOrFiles(rulesDir, fs.Args())
	if err != nil {
		return err
	}

	if inventory != "" {
		return runCheckInventory(ctx, inventory, limit, user, port, keyPath, sudo, format, rules, quiet, outputs)
	}
	if host == "" {
		printCheckUsage(os.Stderr, fs)
		return NewUsageError("--host or --inventory is required")
	}

	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath, Sudo: sudo,
	}
	transport, err := ssh.Factory{}.Connect(ctx, hostCfg)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = transport.Close() }()

	// OS detection runs once per scan: a single `cat /etc/os-release`
	// over the established transport.
	//
	// Missing-file failures (zero exit code, no /etc/os-release) fall
	// through silently — the host banner just omits the OS segment.
	// Transport-level errors (broken pipe, sudo denied, AppArmor)
	// emit a stderr warning so the operator has diagnostic context;
	// the banner still falls back to host-only and the scan
	// continues. Persistent transport problems will resurface
	// immediately on the scan call below.
	osInfo, err := detect.DetectOS(ctx, transport)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kensa: warning: OS detection: %v (banner will omit OS)\n", err)
	}

	// Defensive operator-UX: --verbose only flows through the
	// default text path, not through the writer registry. If the
	// operator combined --verbose with -o, the flag is silently
	// dropped. Surface a one-line warning so the silent demotion
	// doesn't waste a debug session.
	if verbose && len(outputs) > 0 {
		fmt.Fprintln(os.Stderr, "kensa: warning: --verbose only affects the default text output, not -o targets")
	}

	resolved := resolveAndPrintIssues(rules, quiet)

	runner := scan.New(nil)
	result, err := runner.Scan(ctx, transport, resolved.Order)
	if err != nil {
		return err
	}
	result.HostID = host

	if len(outputs) > 0 {
		specs, err := output.ParseAll(outputs)
		if err != nil {
			return WrapUsageError("--output", err)
		}
		return routeFanOutError(output.FanOutScanResult(specs, bodyOut(quiet), host, resolved.Order, result))
	}
	// When the operator picks the default text format, route through
	// RenderScanResult directly so --verbose and the detected OS
	// label can flow into the writer. The fan-out path above does
	// not yet support these — operators wanting verbose+text via
	// fan-out get the default rendering.
	if format == "text" || format == "table" || format == "" {
		return output.RenderScanResult(bodyOut(quiet), host, resolved.Order, result, output.ScanRenderOptions{
			Verbose: verbose,
			OSLabel: osInfo.Label(),
		})
	}
	return output.ScanWriterOrText(format).WriteScanResult(bodyOut(quiet), host, resolved.Order, result)
}

// printCheckUsage writes the `kensa check` help text. --help to stdout,
// usage errors to stderr per GNU.
func printCheckUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa check [flags] [rule.yml ...]

Run read-only compliance checks against one host or an inventory.

Flags:
%s
Examples:
  kensa check -H 192.168.1.211 -u owadmin --sudo -r /path/to/rules
  kensa check --inventory hosts.ini --sudo --rules-dir /path/to/rules
  kensa check -H web-01 -u admin --sudo -o jsonl rule1.yml rule2.yml
`, fs.FlagUsages())
}

// runCheckInventory fans out a check across all hosts in an inventory file.
//
// TODO(post-C-019): collapse the 10 positional parameters into a
// checkOptions struct. The C-019 review flagged this; deferred to
// a separate refactor ticket because changing the signature mid-
// fan-out wiring would obscure the diff.
func runCheckInventory(ctx context.Context, inventoryPath, limit, user string, port int, keyPath string, sudo bool, format string, rules []*api.Rule, quiet bool, outputs []string) error {
	hosts, err := parseInventory(inventoryPath)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	// Apply --limit (C-025) — ansible-style host glob / group filter.
	// Parse errors and "no host matched" surface as usage errors so
	// the operator sees the typo rather than a silent no-op scan.
	if limit != "" {
		filtered, ferr := filterByLimit(hosts, limit)
		if ferr != nil {
			return WrapUsageError("--limit", ferr)
		}
		hosts = filtered
	}
	if len(hosts) == 0 {
		return NewUsageError("--limit produced an empty host set; nothing to scan")
	}

	// Resolve rules once before the per-host fan-out so every host
	// runs the same active set in the same order. cmd/kensa's
	// per-host text rendering today doesn't surface the resolution
	// summary; C-022 weaves that into the host banner.
	resolved := resolveAndPrintIssues(rules, quiet)

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
			res, err := runner.Scan(ctx, transport, resolved.Order)
			if err != nil {
				results[idx] = hostResult{host: ih, err: err}
				return
			}
			res.HostID = ih.addr
			results[idx] = hostResult{host: ih, result: res}
		}(i, h)
	}
	wg.Wait()

	stdoutOverride := bodyOut(quiet)
	if len(outputs) > 0 {
		// Inventory mode + -o: parse specs once; fan out per-host.
		// Each host's result emits N documents (one per spec). For
		// CSV / oscal / evidence formats this concatenates many
		// hosts' per-host documents into one file — operators
		// wanting one canonical CSV file across an inventory should
		// use the streaming wrappers (StreamingCSVScan etc.) — not
		// wired in C-019 because cmd/kensa would need a per-host
		// stream-state, which is post-C-019 polish.
		specs, err := output.ParseAll(outputs)
		if err != nil {
			return WrapUsageError("--output", err)
		}
		for _, r := range results {
			if r.err != nil {
				fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", r.host.addr, r.err)
				continue
			}
			if err := routeFanOutError(output.FanOutScanResult(specs, stdoutOverride, r.host.addr, resolved.Order, r.result)); err != nil {
				return err
			}
		}
		return nil
	}
	w := output.ScanWriterOrText(format)
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", r.host.addr, r.err)
			continue
		}
		if err := w.WriteScanResult(stdoutOverride, r.host.addr, resolved.Order, r.result); err != nil {
			return err
		}
	}
	return nil
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
		quiet    bool
		outputs  []string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table or json (deprecated; use --output)")
	fs.StringVar(&oscalOut, "oscal", "", "write OSCAL Assessment Results to this file (deprecated; use --output oscal:PATH)")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory to scan for *.yml rule files")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")
	fs.StringSliceVarP(&outputs, "output", ShortOutput, nil, "output destination FORMAT[:PATH], repeatable")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printRemediateUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa remediate --help'", err)
	}
	if showHelp {
		printRemediateUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printRemediateUsage(os.Stderr, fs)
		return NewUsageError("--host is required")
	}
	warnDeprecatedFlag(fs, "format", "--output FORMAT[:PATH]")
	warnDeprecatedFlag(fs, "oscal", "--output oscal:PATH")

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
	resolved := resolveAndPrintIssues(rules, quiet)
	result, err := svc.Remediate(ctx, hostCfg, resolved.Order)
	if err != nil {
		return err
	}

	if len(outputs) > 0 {
		specs, err := output.ParseAll(outputs)
		if err != nil {
			return WrapUsageError("--output", err)
		}
		if err := routeFanOutError(output.FanOutRemediationResult(specs, bodyOut(quiet), host, resolved.Order, result)); err != nil {
			return err
		}
	} else if err := output.RemediationWriterOrText(format).WriteRemediationResult(bodyOut(quiet), host, resolved.Order, result); err != nil {
		return err
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
  kensa remediate -H 192.168.1.211 -u owadmin --sudo -r /path/to/rules
  kensa remediate -H web-01 -u admin --sudo -o json -o oscal:/tmp/results.oscal.json
`, fs.FlagUsages())
}


// writeOSCALFile opens path and writes OSCAL Assessment Results
// documents (one per transaction with a non-nil envelope) by
// delegating to the registered "oscal" RemediationResultWriter.
//
// This preserves the legacy --oscal flag's user-visible behavior
// (file open + close handled here) while routing the byte production
// through the same writer the future -o oscal:path mechanism will
// dispatch to (C-018). The two surfaces share one OSCAL serializer
// implementation; deprecating --oscal in a future minor version is
// purely a CLI change.
//
// Empty-envelope short-circuit: when no transaction has an envelope
// (e.g., every rule errored before commit), the function returns
// nil WITHOUT creating the file and logs to stderr. A 0-byte
// "OSCAL" file is operator-hostile — auditors opening it cannot
// distinguish "Kensa crashed" from "the run had no envelopes" from
// "the file was truncated." Better to leave no artifact and tell
// the operator why.
func writeOSCALFile(path string, result *api.RemediationResult) error {
	envelopes := 0
	for _, txr := range result.Transactions {
		if txr.Envelope != nil {
			envelopes++
		}
	}
	if envelopes == 0 {
		fmt.Fprintln(os.Stderr, "kensa: --oscal: no remediation envelopes produced; no OSCAL output written")
		return nil
	}
	w, ok := output.RemediationWriterFor("oscal")
	if !ok {
		return fmt.Errorf("kensa: oscal writer not registered (build invariant broken)")
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return w.WriteRemediationResult(f, "", nil, result)
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
		quiet    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&txnIDStr, "txn", ShortTransaction, "", "transaction UUID to roll back (required)")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printRollbackUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa rollback --help'", err)
	}
	if showHelp {
		printRollbackUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printRollbackUsage(os.Stderr, fs)
		return NewUsageError("--host is required")
	}
	if txnIDStr == "" {
		printRollbackUsage(os.Stderr, fs)
		return NewUsageError("--txn is required")
	}
	txnID, err := uuid.Parse(txnIDStr)
	if err != nil {
		return WrapUsageError("invalid --txn UUID", err)
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
	jw, _ := output.JSONValueWriterFor("json")
	return jw.WriteJSONValue(bodyOut(quiet), result)
}

// printRollbackUsage writes the `kensa rollback` help text to w.
func printRollbackUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa rollback [flags]

Roll back a past transaction by ID using captured pre-state.

Flags:
%s
Example:
  kensa rollback -H 192.168.1.211 -u owadmin --sudo -T 8c3a1e2b-...
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
		quiet     bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&hostID, "host", ShortHost, "", "filter by host ID")
	fs.StringVarP(&ruleID, "rule", ShortRule, "", "filter by rule ID")
	fs.StringVarP(&since, "since", ShortSince, "", "filter since duration (e.g. 24h) or RFC3339 time")
	fs.IntVarP(&limit, "limit", ShortLimit, 50, "maximum rows to return")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table or json")
	fs.StringVarP(&txnIDStr, "txn", ShortTransaction, "", "get a single transaction by UUID")
	fs.StringVarP(&aggregate, "aggregate", ShortAggregate, "", "aggregate key: by_host, by_rule, by_framework_control")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printHistoryUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa history --help'", err)
	}
	if showHelp {
		printHistoryUsage(os.Stdout, fs)
		return nil
	}

	// Validate flag values up front (fail-fast on bad input before
	// touching the store). All UsageError paths must run before any
	// runtime resource is acquired.
	var txnID uuid.UUID
	if txnIDStr != "" {
		var err error
		txnID, err = uuid.Parse(txnIDStr)
		if err != nil {
			return WrapUsageError("invalid --txn UUID", err)
		}
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
			return WrapUsageError("--since", err)
		}
		filter.Since = t
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

	jsonValue, _ := output.JSONValueWriterFor("json")
	out := bodyOut(quiet)

	if txnIDStr != "" {
		rec, err := log.Get(ctx, txnID)
		if err != nil {
			return fmt.Errorf("get transaction: %w", err)
		}
		return jsonValue.WriteJSONValue(out, rec)
	}

	if aggregate != "" {
		aggResult, err := log.Aggregate(ctx, filter, api.AggregateKey(aggregate))
		if err != nil {
			return fmt.Errorf("aggregate: %w", err)
		}
		return jsonValue.WriteJSONValue(out, aggResult)
	}

	result, err := log.Query(ctx, filter, api.Page{Limit: limit})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	if format == "json" {
		return jsonValue.WriteJSONValue(out, result)
	}
	w := output.HistoryWriterOrText(format)
	if err := w.WriteHistory(out, result.Transactions); err != nil {
		return err
	}
	// The "N of M transactions shown" trailer is human-friendly footer
	// text. It is correct for the text writer (humans read tables top-
	// to-bottom) but corrupts row-oriented formats (CSV) that downstream
	// tools parse as a flat row stream. For CSV the trailer goes to
	// stderr so the operator still sees pagination context without
	// breaking the output file.
	if w.Format() == "text" {
		// Trailer is part of the human-readable body; --quiet suppresses
		// it alongside the table itself.
		fmt.Fprintf(out, "\n%d of %d transactions shown\n", len(result.Transactions), result.Total)
	} else {
		// CSV/etc.: trailer goes to stderr (it would corrupt a row-
		// oriented format if mixed into stdout). stderr is not
		// silenced by --quiet — the pagination context is helpful
		// regardless.
		fmt.Fprintf(os.Stderr, "%d of %d transactions shown\n", len(result.Transactions), result.Total)
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
  kensa history -T 8c3a1e2b-...                  # one transaction by UUID
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
		quiet    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text, markdown, json, plain")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printPlanUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa plan --help'", err)
	}
	if showHelp {
		printPlanUsage(os.Stdout, fs)
		return nil
	}
	if host == "" {
		printPlanUsage(os.Stderr, fs)
		return NewUsageError("--host is required")
	}
	if fs.NArg() == 0 {
		printPlanUsage(os.Stderr, fs)
		return NewUsageError("a rule YAML file is required")
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

	planText, err := engine.FormatPlan(plan, api.PreviewFormat(format))
	if err != nil {
		return err
	}
	fmt.Fprint(bodyOut(quiet), planText)
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
  kensa plan -H 192.168.1.211 -u owadmin --sudo --format markdown rule.yml
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
		return WrapUsageError("try 'kensa coverage --help'", err)
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
		return WrapUsageError("try 'kensa version --help'", err)
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
		return nil, NewUsageError("at least one rule YAML file or --rules-dir is required")
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
	// groups lists the [group] sections this host belongs to.
	// Empty when the host appears in a section-less prelude.
	// Used by --limit (C-025) for ansible-style group-name
	// matching.
	groups []string
}

// parseInventory reads an Ansible-style INI inventory file and returns
// all host entries. Lines starting with '#' are comments; lines like
// `[group]` start a new section and accumulate as group memberships
// for subsequent host lines. Host lines have the form:
//
//	<addr>  [ansible_user=<user>]  [ansible_port=<port>]
//
// A host that appears under multiple `[group]` headers gathers all
// group names; --limit (C-025) matches against any of them.
func parseInventory(path string) ([]inventoryHost, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Track host index by addr so duplicate entries (the same host
	// listed under two groups) merge their group memberships
	// rather than producing duplicate hosts in the output.
	byAddr := map[string]int{}
	var hosts []inventoryHost
	currentGroup := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// New group header. Strip "[group:children]" /
			// "[group:vars]" qualifiers — kensa only honors host
			// memberships, not the children/vars hierarchy.
			name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if idx := strings.Index(name, ":"); idx > 0 {
				name = name[:idx]
			}
			currentGroup = name
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
		if i, exists := byAddr[h.addr]; exists {
			// Merge group memberships into the existing entry.
			if currentGroup != "" && !containsString(hosts[i].groups, currentGroup) {
				hosts[i].groups = append(hosts[i].groups, currentGroup)
			}
			continue
		}
		if currentGroup != "" {
			h.groups = []string{currentGroup}
		}
		byAddr[h.addr] = len(hosts)
		hosts = append(hosts, h)
	}
	return hosts, scanner.Err()
}

// containsString is a tiny helper for the duplicate-group check
// in parseInventory.
func containsString(s []string, target string) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
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

