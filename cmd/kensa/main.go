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
//	mechanisms  List registered handler mechanisms.
//	coverage    Alias for `mechanisms` today; v0.2 will repurpose this name
//	            for framework control coverage. Migrate to `mechanisms` now.
//	list        Introspection commands (`kensa list frameworks`).
//	info        Rule/control lookup (multi-criteria search over the corpus).
//	diff        Compare two stored sessions and emit per-rule drift.
//	agent       Run kensa as a stdio agent on the target host; see `kensa agent --help`.
//	verify      Validate the Ed25519 signature on an evidence-envelope JSON file.
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
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/dispatcher"
	"github.com/Hanalyx/kensa/internal/detect"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/output"
	"github.com/Hanalyx/kensa/internal/rule"
	rulespath "github.com/Hanalyx/kensa/internal/rules"
	"github.com/Hanalyx/kensa/internal/scan"
	"github.com/Hanalyx/kensa/internal/store"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
	"github.com/Hanalyx/kensa/internal/varsub"
	"github.com/Hanalyx/kensa/pkg/kensa"
	// Apply-mechanism handlers register transitively via pkg/kensa, which
	// blank-imports the pkg/kensa/handlers bundle — the single source of
	// truth shared with external consumers (issue #94). The CLI no longer
	// carries its own handler list, so the two sets cannot diverge.
)

// version is the kensa binary version string surfaced by --version
// and the `version` subcommand. Set by -ldflags "-X main.version=$(cat VERSION)"
// at build time per VERSIONING_PLAN.md. Defaults to "dev" so `go run`
// works locally without invoking make.
var version = "dev"

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
	argv = rewriteLegacyDB(argv)

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
	topFlags.StringVarP(&dbPath, "db", ShortDB, "", "SQLite transaction-log path (default: .kensa/results.db)")

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
		fmt.Printf("kensa %s (kensa)\n", version)
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
		err = runCheck(ctx, dbPath, args)
	case "remediate":
		err = runRemediate(ctx, dbPath, args)
	case "rollback":
		err = runRollback(ctx, dbPath, args)
	case "history":
		err = runHistory(ctx, dbPath, args)
	case "plan":
		err = runPlan(ctx, dbPath, args)
	case "mechanisms":
		// C-045: --framework on `mechanisms` is a usage error
		// pointing the operator at `kensa coverage`. Detected
		// via the same hasFrameworkFlag scanner used at the
		// `coverage` dispatch — keeps the rejection consistent
		// with the routing decision.
		if hasFrameworkFlag(args) {
			err = NewUsageError("--framework is for 'kensa coverage' (the framework-coverage report); 'kensa mechanisms' lists registered handler mechanisms")
		} else {
			err = runMechanisms("mechanisms", args)
		}
	case "coverage":
		if hasFrameworkFlag(args) {
			// C-045 NEW behavior. The operator is using the
			// framework-coverage report — they've embraced the
			// v0.2 semantics today, so suppress the repurpose
			// warning when actually running the report (it
			// would be noise about a flip the operator already
			// crossed). EXCEPTION: emit it on --help, because
			// --help is the discoverability surface where
			// operators read docs and the v0.2 flip is exactly
			// what they're trying to learn.
			if hasHelpFlag(args) {
				warnRepurposedSubcommand(
					"kensa coverage",
					"kensa mechanisms",
					"framework control coverage")
			}
			err = runCoverageReport(args)
		} else {
			// C-044 deprecation alias path. Without --framework,
			// `kensa coverage` is still the mechanism listing.
			// Warn so the operator migrates before v0.2 flips
			// the no-flag case too.
			warnRepurposedSubcommand(
				"kensa coverage",
				"kensa mechanisms",
				"framework control coverage")
			err = runMechanisms("coverage", args)
		}
	case "list":
		// C-046: introspection namespace. C-046 wired
		// `frameworks`; C-048 added `sessions` to surface
		// session IDs for `kensa diff`.
		err = runList(ctx, dbPath, args)
	case "info":
		// C-047: multi-criteria rule/control lookup.
		err = runInfo(ctx, args)
	case "diff":
		// C-048: per-rule drift between two stored sessions.
		err = runDiff(ctx, dbPath, args)
	case "agent":
		// L-008 (agent-stdio-subcommand): --stdio runs the
		// echo loop (read framed Request → mirror as Response).
		// L-009 replaces the echo handler with the real Engine
		// dispatcher. C-054's v1.0 placeholder behavior is
		// superseded; the bare-invocation, --help, and --bogus
		// contracts from cli-agent-placeholder are preserved.
		err = runAgent(args)
	case "verify":
		// C-060: validate signed evidence envelope from disk
		// against a trust directory of .pub files.
		err = runVerify(args)
	case "migrate":
		err = runMigrate(ctx, dbPath, args)
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
// pre-existing legacy-flag warnings (rewriteLegacyDB,
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

// warnRepurposedSubcommand emits a stderr warning when an
// operator invokes a subcommand whose NAME will be repurposed
// in a future version. Distinct from warnDeprecatedFlag, where
// the flag and its semantics both go away together: here the
// name survives but its output changes. An operator's script
// running `kensa <name>` continues to exit 0 in v0.2 — but
// produces different rows. That silent semantic flip is what
// this warning is paid to prevent.
//
// Two-knob suppression contract:
//   - KENSA_NO_REPURPOSE_WARNINGS=1: silences ONLY repurpose
//     warnings. Use this for CI scripts that have explicitly
//     ack'd the upcoming semantic flip and migrated.
//   - KENSA_NO_DEPRECATION_WARNINGS=1: silences flag-rename
//     warnings (warnDeprecatedFlag) but does NOT silence this
//     one. Operators who silenced flag warnings months ago
//     deserve to still see the louder repurpose signal —
//     coupling the two switches creates a documented
//     foot-gun where a stale CI silence masks a real
//     scripted-output break.
//
// Wording uses "repurposed," not "deprecated," to avoid the
// "feature is going away" misread. The example in the spec is
// `kensa coverage` (current: handler-mechanism listing; v0.2:
// framework control coverage reporting).
func warnRepurposedSubcommand(name, currentReplacement, futurePurpose string) {
	if os.Getenv("KENSA_NO_REPURPOSE_WARNINGS") == "1" {
		return
	}
	fmt.Fprintf(os.Stderr,
		"kensa: warning: '%s' will change meaning in v0.2 (it will report %s).\n"+
			"               For the current output, switch to '%s' before upgrading.\n",
		name, futurePurpose, currentReplacement)
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
// Info-prefixed lines (supersedes notices) are suppressed when
// quiet is true so CI scripts running --quiet don't drown in
// cosmetic chatter. Error and warning lines (cycles, dropped
// rules, conflicts) always emit — operators must see real
// configuration problems regardless of --quiet.
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

// rewriteLegacyDB converts stdlib-flag-style single-dash `-db ...` and
// `-db=...` to pflag's `--db ...` and `--db=...`. Emits a deprecation
// warning to stderr so users see they need to migrate the syntax.
// Scope is intentionally narrow: only -db (the only top-level long flag
// that previously worked with single dash). Subcommand-level legacy
// flags will be handled by their own backward-compat shims as they
// migrate to pflag (deliverables C-002..C-004).
func rewriteLegacyDB(argv []string) []string {
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
  mechanisms  List registered handler mechanisms
  coverage    Alias for 'mechanisms' today; in v0.2 reports framework
              control coverage instead — migrate scripts to 'mechanisms'
  list        Introspection commands ('kensa list frameworks', etc.)
  info        Rule/control lookup (multi-criteria search over the corpus)
  diff        Compare two stored sessions and emit per-rule drift
  agent       Run kensa as a stdio agent on the target host; see 'kensa agent --help'
  verify      Validate the Ed25519 signature on an evidence-envelope JSON file
  migrate     Apply pending schema migrations and backfill legacy sessions
  version     Print version and exit

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
		showHelp     bool
		host         string
		user         string
		port         int
		keyPath      string
		password     string
		sudo         bool
		sudoPassword string
		format       string
		quiet        bool
		outputs      []string
		capabilities []string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	registerPasswordFlag(fs, &password)
	registerStrictHostKeysFlag(fs)
	registerCapabilityFlag(fs, &capabilities)
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	registerSudoPasswordFlag(fs, &sudoPassword)
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

	// Flag-only constraints up front, before SSH setup. Bad
	// --password, --strict-host-keys conflicts, or malformed
	// --capability entries should surface before we open a transport.
	resolvedPwd, err := resolvePassword(password, os.Stdin, os.Stderr)
	if err != nil {
		return &UsageError{Cause: err}
	}
	resolvedSudoPwd, err := resolveSudoPasswordFor(fs, sudoPassword, sudo, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	strictHostKeys, err := resolveStrictHostKeys(fs)
	if err != nil {
		return err
	}
	overrides, err := resolveCapabilityOverrides(capabilities)
	if err != nil {
		return &UsageError{Cause: err}
	}

	hostCfg := api.HostConfig{
		Hostname:       host,
		User:           user,
		Port:           port,
		KeyPath:        keyPath,
		Password:       resolvedPwd,
		StrictHostKeys: strictHostKeys,
		Sudo:           sudo,
		SudoPassword:   resolvedSudoPwd,
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
	// C-028: apply --capability KEY=VALUE overrides on top of the
	// detected set so the operator-facing display reflects what
	// scan/remediate would actually see.
	caps = detect.ApplyOverrides(caps, overrides)

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

%s

Examples:
  kensa detect -H 192.168.1.211 -u owadmin --sudo
  kensa detect --host web-01 --user admin --format json
`, formatGroupedUsages(fs, detectFlagGroups))
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
func runCheck(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true, "key": true,
		"sudo": true, "format": true, "rules-dir": true, "inventory": true,
	})

	fs := pflag.NewFlagSet("check", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp     bool
		host         string
		user         string
		port         int
		keyPath      string
		password     string
		sudo         bool
		sudoPassword string
		format       string
		rulesDir     string
		inventory    string
		limit        string
		quiet        bool
		verbose      bool
		outputs      []string
		capabilities []string
		workers      int
		severities   []string
		tags         []string
		category     string
		framework    string
		controls     []string
		ruleFiles    []string
		varOverrides []string
		configDir    string
		storeFlag    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required if no --inventory)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	registerPasswordFlag(fs, &password)
	registerStrictHostKeysFlag(fs)
	registerCapabilityFlag(fs, &capabilities)
	registerSeverityFlag(fs, &severities)
	registerTagFilterFlag(fs, &tags)
	registerCategoryFlag(fs, &category)
	registerFrameworkFlag(fs, &framework)
	registerControlFilterFlag(fs, &controls)
	registerRuleFileFlag(fs, &ruleFiles)
	registerVarFlag(fs, &varOverrides)
	registerConfigDirFlag(fs, &configDir)
	fs.BoolVar(&storeFlag, "store", false, "persist the scan as a session+transactions record in the SQLite store (default off; check is read-only by default)")
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	registerSudoPasswordFlag(fs, &sudoPassword)
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table, json, or jsonl (deprecated; use --output)")
	fs.StringVarP(&rulesDir, "rules-dir", ShortRulesDir, "", "directory to scan for *.yml rule files")
	fs.StringVarP(&inventory, "inventory", ShortInventory, "", "Ansible-style inventory.ini for multi-host check")
	fs.StringVarP(&limit, "limit", ShortLimitGlob, "", "limit inventory hosts to glob/group pattern (ansible --limit semantics)")
	registerWorkersFlag(fs, &workers)
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

	// Flag-only validations up front, before rule load and SSH
	// setup. Bad --strict-host-keys conflicts, malformed
	// --capability, out-of-range --workers, or unknown --severity
	// should surface before we touch the filesystem.
	strictHostKeys, err := resolveStrictHostKeys(fs)
	if err != nil {
		return err
	}
	capOverrides, err := resolveCapabilityOverrides(capabilities)
	if err != nil {
		return &UsageError{Cause: err}
	}
	if err := validateWorkers(workers); err != nil {
		// validateWorkers errors already begin with "--workers"; wrap
		// without an extra prefix so we don't get "--workers: --workers
		// must be >= 1...".
		return &UsageError{Cause: err}
	}
	resolvedSeverities, err := validateSeverities(severities)
	if err != nil {
		return &UsageError{Cause: err}
	}
	normalizedTags := normalizeTags(tags)

	// Resolve variable substitution before rule load.
	// Priority chain (highest first, per Python kensa):
	//   1. CLI --var KEY=VALUE
	//   2. <config-dir>/hosts/<host>.yml          (single-host only)
	//   3. <config-dir>/groups/<group>.yml         (inventory only)
	//   4. <config-dir>/conf.d/*.yml (alphabetical)
	//   5. <config-dir>/defaults.yml
	//
	// In single-host mode, full 5-tier resolution; the host name is
	// taken from --host. Inventory mode handles its own per-host
	// merge inside runCheckInventory using the host name + groups
	// from the parsed inventory, but as a pragmatic simplification
	// only the 3 "global" tiers (defaults + conf.d + CLI) are
	// active there — true per-host / per-group inventory vars
	// require re-loading the corpus per host, deferred to Phase
	// 3.7 if demand surfaces.
	cliVars, err := resolveVarOverrides(varOverrides)
	if err != nil {
		return &UsageError{Cause: err}
	}

	// Auto-detect chain for --config-dir (C-036): operator-supplied
	// value > $KENSA_CONFIG_DIR > $XDG_CONFIG_HOME/kensa >
	// $HOME/.config/kensa > /etc/kensa. Returns "" when no
	// candidate exists; operators still get the embedded built-in
	// defaults via the lowest tier in ResolveTiers.
	configDir = resolveConfigDir(configDir)

	// In single-host mode the host name is known at flag-parse
	// time and the per-host file <config-dir>/hosts/<host>.yml is
	// part of the resolution. In inventory mode, each
	// per-host goroutine in runCheckInventory resolves its own
	// chain using the inventory's host address and group
	// memberships; the global pre-load below uses the host-
	// independent tiers only and serves filter-vocab validation.
	loadHostname := host
	if inventory != "" {
		loadHostname = "" // per-host vars resolved per-goroutine in 3.7
	}
	loadVars, err := varsub.ResolveTiers(configDir, loadHostname, nil, cliVars)
	if err != nil {
		return WrapUsageError("--config-dir", err)
	}

	// C-037: --rule values + positional *.yml args combine into the
	// strict-load file set. With --rules-dir set, the dir-walk and
	// the strict file set load additively.
	rules, err := loadRulesFromDirOrFiles(rulesDir, concatPaths(ruleFiles, fs.Args()), loadVars)
	if err != nil {
		return err
	}
	// C-033: snapshot the framework vocabulary BEFORE filtering so an
	// "unknown framework" error reflects what the loaded corpus
	// actually contains, not what survives the severity/tag/category
	// chain. An operator running `-s critical -f nist_800_53` against
	// a corpus where critical rules have no NIST mappings should see
	// "no rules matched (after upstream filters)", not "unknown
	// framework" — those are different failure modes.
	loadedFrameworks := availableFrameworks(rules)
	canonicalFramework, err := validateFramework(framework, loadedFrameworks)
	if err != nil {
		return &UsageError{Cause: err}
	}
	// C-035: parse + validate --control filters against the
	// pre-filter corpus, same rationale as --framework above.
	controlFilters, err := parseControlFilters(controls)
	if err != nil {
		return &UsageError{Cause: err}
	}
	if err := validateControls(controlFilters, rules); err != nil {
		return &UsageError{Cause: err}
	}
	// C-030: --severity filter at load time.
	rules = filterRulesBySeverity(rules, resolvedSeverities)
	if len(resolvedSeverities) > 0 && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--severity %v: no rules matched; nothing to scan", resolvedSeverities))
	}
	// C-031: --tag filter on top of --severity (AND across filter
	// types: severity narrows first, tags narrow further). When the
	// tag filter empties the set, surface the pre-tag count so the
	// operator can tell whether severity or tag killed the run.
	preTagCount := len(rules)
	rules = filterRulesByTag(rules, normalizedTags)
	if len(normalizedTags) > 0 && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--tag %v: no rules matched (after --severity filter, %d rule(s) remained; none had matching tags)", normalizedTags, preTagCount))
	}
	// C-032: --category filter, narrows further (AND with --severity
	// and --tag). Empty-after-filter discloses pre-category count.
	preCategoryCount := len(rules)
	rules = filterRulesByCategory(rules, category)
	if category != "" && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--category %q: no rules matched (after upstream filters, %d rule(s) remained; none had matching category)", category, preCategoryCount))
	}
	// C-033: framework filter (validation already happened above
	// against the pre-filter corpus snapshot).
	preFrameworkCount := len(rules)
	rules = filterRulesByFramework(rules, canonicalFramework)
	if canonicalFramework != "" && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--framework %q: no rules matched (after upstream filters, %d rule(s) remained; none mapped this framework)", framework, preFrameworkCount))
	}
	// C-035: --control filter (validation also happened above).
	preControlCount := len(rules)
	rules = filterRulesByControl(rules, controlFilters)
	if len(controlFilters) > 0 && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--control %v: no rules matched (after upstream filters, %d rule(s) remained; none mapped any of these controls)", controls, preControlCount))
	}

	if inventory != "" {
		// --password is single-host only: inventory hosts may have
		// different credentials and broadcasting one password
		// across the fleet would be a footgun. Operators with a
		// shared password should set SSHPASS in the environment;
		// per-host password support in inventory files is a
		// future deliverable.
		if password != "" {
			printCheckUsage(os.Stderr, fs)
			return NewUsageError("--password is not allowed with --inventory; use SSHPASS env or per-host config")
		}
		// Same footgun for --sudo-password inline: one sudo password
		// broadcast across a heterogeneous fleet. A shared sudo
		// password is supported through the KENSA_SUDO_PASSWORD env
		// var, which the inventory fan-out applies to each host.
		if fs.Changed("sudo-password") {
			printCheckUsage(os.Stderr, fs)
			return NewUsageError("--sudo-password is not allowed with --inventory; set " + sudoPasswordEnv + " env for a shared sudo password")
		}
		// C-041: --store wires session+transactions persistence
		// in the single-host path only. The inventory fan-out
		// goroutine doesn't yet write to the store; silent
		// acceptance would create a session with zero attached
		// transactions on inventory runs. Surface the limit as
		// a usage error until a future deliverable wires the
		// per-host write path.
		if storeFlag {
			printCheckUsage(os.Stderr, fs)
			return NewUsageError("--store with --inventory not yet supported; pending follow-up to wire per-host store writes in inventory fan-out")
		}
		// Phase 3.7: pass the load+filter spec + per-host tier
		// inputs into the inventory fan-out so each goroutine
		// can re-load the corpus with that host's full 5-tier
		// resolved variables.
		spec := ruleLoadFilterSpec{
			rulesDir:       rulesDir,
			rulePaths:      concatPaths(ruleFiles, fs.Args()),
			severities:     resolvedSeverities,
			tags:           normalizedTags,
			category:       category,
			framework:      canonicalFramework,
			controlFilters: controlFilters,
		}
		return runCheckInventory(ctx, inventory, limit, user, port, keyPath, sudo, strictHostKeys, capOverrides, workers, format, spec, configDir, cliVars, quiet, outputs)
	}
	if host == "" {
		printCheckUsage(os.Stderr, fs)
		return NewUsageError("--host or --inventory is required")
	}

	resolvedPwd, err := resolvePassword(password, os.Stdin, os.Stderr)
	if err != nil {
		return &UsageError{Cause: err}
	}
	resolvedSudoPwd, err := resolveSudoPasswordFor(fs, sudoPassword, sudo, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}

	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath,
		Password: resolvedPwd, StrictHostKeys: strictHostKeys, Sudo: sudo,
		SudoPassword: resolvedSudoPwd,
		Capabilities: capOverrides,
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

	// Default human output (text/table with no -o sink) streams the
	// result rows live — one aligned row per rule, in scan order, printed
	// as each rule's check completes — matching the reference kensa.
	// Columns: STATUS  SEVERITY  RULE-ID  DESCRIPTION. The rows ARE the
	// canonical text rendering, so they go to the result stream (stdout);
	// the returned ScanResult is unchanged. Machine formats (json/jsonl)
	// and -o sinks stay buffered/structured below — no live rows.
	streamText := len(outputs) == 0 && (format == "text" || format == "table" || format == "")
	var streamWriter *output.StreamScanWriter
	var scanOpts []scan.Option
	if streamText {
		streamWriter = output.NewStreamScanWriter(bodyOut(quiet), stdoutIsTerminal() && !quiet, resolved.Order)
		if !quiet {
			streamWriter.Banner(host, osInfo.Label())
		}
		scanOpts = append(scanOpts, scan.WithProgress(streamWriter))
	}
	runner := scan.New(nil, scanOpts...)
	startedAt := time.Now().UTC()
	result, err := runner.ScanWithOverrides(ctx, transport, resolved.Order, capOverrides)
	if err != nil {
		return err
	}
	result.HostID = host

	// C-041: persist the scan as a session+transactions record
	// when --store is set. Best-effort — a store failure logs
	// to stderr but does not fail the scan (operator already has
	// the result on stdout / output sinks).
	if storeFlag {
		s, err := store.OpenSQLite(ctx, dbPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: --store: open store: %v\n", err)
		} else {
			sess := &store.Session{
				ID:          uuid.New(),
				StartedAt:   startedAt,
				Hostname:    host,
				Subcommand:  "check",
				ArgsSummary: summarizeCheckArgs(severities, tags, category, framework, controlFilters),
			}
			if _, err := persistScanResult(ctx, s, host, resolved.Order, result, sess); err != nil {
				fmt.Fprintf(os.Stderr, "warn: --store: persist scan: %v\n", err)
			}
			_ = s.Close()
		}
	}

	// Default human path: the rows already streamed live during the scan;
	// close with the tally line.
	if streamText {
		if !quiet {
			streamWriter.Summary()
		}
		return nil
	}
	if len(outputs) > 0 {
		specs, err := output.ParseAll(outputs)
		if err != nil {
			return WrapUsageError("--output", err)
		}
		// `-o evidence:` emits the native-evidence document, which needs the
		// session/host context (command, effective variables) the generic
		// scan-writer interface cannot carry. Split those specs off and write
		// them with that context; the rest fan out as usual.
		var evSpecs, otherSpecs []output.Spec
		for _, s := range specs {
			if s.Format == "evidence" {
				evSpecs = append(evSpecs, s)
			} else {
				otherSpecs = append(otherSpecs, s)
			}
		}
		if len(evSpecs) > 0 {
			ev := output.NativeEvidenceInput{
				SessionID:          uuid.New().String(),
				Timestamp:          startedAt,
				Command:            "check",
				Hostname:           host,
				Result:             result,
				Rules:              resolved.Order,
				EffectiveVariables: loadVars,
			}
			if err := routeFanOutError(output.FanOutNativeEvidence(evSpecs, bodyOut(quiet), ev)); err != nil {
				return err
			}
		}
		if len(otherSpecs) > 0 {
			return routeFanOutError(output.FanOutScanResult(otherSpecs, bodyOut(quiet), host, resolved.Order, result))
		}
		return nil
	}
	// Non-streaming machine formats (e.g. --format json/jsonl without -o)
	// stay buffered and structured.
	return output.ScanWriterOrText(format).WriteScanResult(bodyOut(quiet), host, resolved.Order, result)
}

// printCheckUsage writes the `kensa check` help text. --help to stdout,
// usage errors to stderr per GNU.
func printCheckUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa check [flags] [rule.yml ...]

Run read-only compliance checks against one host or an inventory.

%s

Examples:
  kensa check -H 192.168.1.211 -u owadmin --sudo -r /path/to/rules
  kensa check --inventory hosts.ini --sudo --rules-dir /path/to/rules
  kensa check --inventory hosts.ini -w 10 --sudo -r /path/to/rules
  kensa check -H 192.168.1.211 -s critical -s high -r /path/to/rules
  kensa check -H 192.168.1.211 -f cis-rhel9 --control cis_rhel9:5.1.12 -r /path/to/rules
  kensa check -H web-01 -u admin --sudo -o jsonl rule1.yml rule2.yml
`, formatGroupedUsages(fs, checkFlagGroups))
}

// runCheckInventory fans out a check across all hosts in an inventory file.
//
// TODO(post-C-019): collapse the 10 positional parameters into a
// checkOptions struct. The C-019 review flagged this; deferred to
// a separate refactor ticket because changing the signature mid-
// fan-out wiring would obscure the diff.
func runCheckInventory(ctx context.Context, inventoryPath, limit, user string, port int, keyPath string, sudo, strictHostKeys bool, capOverrides api.CapabilitySet, workers int, format string, spec ruleLoadFilterSpec, configDir string, cliVars varsub.Variables, quiet bool, outputs []string) error {
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

	// C-029: nudge operators toward the concurrency knob on
	// non-trivial fleets. We only emit the hint when --workers was
	// left at its default of 1 — operators who explicitly chose 1
	// (or any other value) get silence.
	if workers == 1 && len(hosts) > LargeFleetThreshold && !quiet {
		fmt.Fprintf(os.Stderr,
			"kensa check: %d hosts in inventory and --workers=1 (sequential); pass -w 5 or higher to scan in parallel\n",
			len(hosts))
	}

	// Phase 3.7: each host's goroutine re-loads the corpus with
	// that host's full 5-tier resolved variables. We DO print
	// rule-resolution issues once up front using the global-tier
	// rule set — those issues (conflicts, cycles, supersedes
	// chains) operate on corpus-property fields that don't vary
	// with substitution, so per-host printing would be redundant
	// noise.
	//
	// The validation pass uses the host-independent tiers
	// (defaults + conf.d + CLI) — passing hostname="" and
	// groups=nil to ResolveTiers gets just those. This handles
	// templated rules whose `{{ var }}` is defined in defaults.yml
	// or conf.d/*.yml; the per-host file may override but is not
	// required for the global pass to succeed.
	globalVars, err := varsub.ResolveTiers(configDir, "", nil, cliVars)
	if err != nil {
		return err
	}
	globalRules, err := spec.LoadAndFilter(globalVars)
	if err != nil {
		return err
	}
	// Print rule-resolution issues once (conflicts / cycles /
	// supersedes chains operate on corpus-property fields that
	// don't vary with substitution; per-host re-printing would
	// be redundant noise). Discard the returned ResolvedRules
	// — rendering uses each host's own resolved slice (see
	// hostResult.rules).
	_ = resolveAndPrintIssues(globalRules, quiet)

	type hostResult struct {
		host inventoryHost
		// rules is this host's filtered+resolved rule slice in
		// execution order. Phase 3.7: each host has its own
		// rule slice because per-host vars produce different
		// substituted values. The output renderer iterates
		// against this per-host slice (positional alignment
		// with result.Transactions) — using the global slice
		// here would mis-align rows when a rule's `{{ var }}`
		// is defined ONLY in hosts/<addr>.yml (skipped in the
		// global pre-load, loaded in the per-host pass).
		rules  []*api.Rule
		result *api.ScanResult
		err    error
	}

	results := make([]hostResult, len(hosts))

	// C-029: per-host work runs through fanOutBounded which caps
	// concurrent goroutines at `workers` (1-50, validated upstream).
	// fanOutBounded honors ctx cancellation between items.
	fanOutBounded(ctx, hosts, workers, func(idx int, ih inventoryHost) {
		u := ih.user
		if user != "" {
			u = user
		}
		p := port
		if ih.port != 0 {
			p = ih.port
		}
		// Phase 3.7: resolve this host's full 5-tier variable
		// set — defaults + conf.d + groups (from inventory) +
		// hosts/<addr>.yml + CLI override. Then re-load the
		// corpus with these vars and apply the same filter
		// chain. Filter VOCABULARY (severity / framework /
		// control) was validated up front against the
		// global-tier corpus; per-host filtering operates on
		// the same rule-property fields (severity / tags /
		// category / framework refs) which don't vary with
		// substitution, so the post-filter rule SET is
		// identical per host — only the rule VALUES differ.
		hostVars, err := varsub.ResolveTiers(configDir, ih.addr, ih.groups, cliVars)
		if err != nil {
			results[idx] = hostResult{host: ih, err: fmt.Errorf("resolve vars: %w", err)}
			return
		}
		hostRules, err := spec.LoadAndFilter(hostVars)
		if err != nil {
			results[idx] = hostResult{host: ih, err: err}
			return
		}
		hostResolved := rule.Resolve(hostRules)
		hostCfg := api.HostConfig{
			Hostname: ih.addr, User: u, Port: p, KeyPath: keyPath,
			StrictHostKeys: strictHostKeys, Sudo: sudo,
			SudoPassword: inventorySudoPassword(sudo),
			Capabilities: capOverrides,
		}
		transport, err := ssh.Factory{}.Connect(ctx, hostCfg)
		if err != nil {
			results[idx] = hostResult{host: ih, err: fmt.Errorf("connect: %w", err)}
			return
		}
		defer func() { _ = transport.Close() }()
		runner := scan.New(nil)
		res, err := runner.ScanWithOverrides(ctx, transport, hostResolved.Order, capOverrides)
		if err != nil {
			results[idx] = hostResult{host: ih, err: err}
			return
		}
		res.HostID = ih.addr
		results[idx] = hostResult{host: ih, rules: hostResolved.Order, result: res}
	})

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
			// Phase 3.7: render against this host's own rule
			// slice (r.rules), not the global resolved.Order.
			// A rule whose `{{ var }}` is defined only in
			// hosts/<addr>.yml is absent from the global pass
			// but present in r.rules — the renderer's
			// positional alignment with r.result.Transactions
			// must use r.rules to avoid silent misalignment.
			if err := routeFanOutError(output.FanOutScanResult(specs, stdoutOverride, r.host.addr, r.rules, r.result)); err != nil {
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
		// Phase 3.7: render against r.rules (per-host slice),
		// not resolved.Order. See FanOutScanResult site above
		// for the rationale.
		if err := w.WriteScanResult(stdoutOverride, r.host.addr, r.rules, r.result); err != nil {
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
		showHelp     bool
		host         string
		user         string
		port         int
		keyPath      string
		password     string
		sudo         bool
		sudoPassword string
		format       string
		oscalOut     string
		rulesDir     string
		quiet        bool
		outputs      []string
		capabilities []string
		severities   []string
		tags         []string
		category     string
		framework    string
		controls     []string
		ruleFiles    []string
		varOverrides []string
		configDir    string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	registerPasswordFlag(fs, &password)
	registerStrictHostKeysFlag(fs)
	registerCapabilityFlag(fs, &capabilities)
	registerSeverityFlag(fs, &severities)
	registerTagFilterFlag(fs, &tags)
	registerCategoryFlag(fs, &category)
	registerFrameworkFlag(fs, &framework)
	registerControlFilterFlag(fs, &controls)
	registerRuleFileFlag(fs, &ruleFiles)
	registerVarFlag(fs, &varOverrides)
	registerConfigDirFlag(fs, &configDir)
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	registerSudoPasswordFlag(fs, &sudoPassword)
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

	// Validate flag-only constraints up front, before any expensive
	// setup (rule load, store open). Operators with both
	// --strict-host-keys and --no-strict-host-keys (or a malformed
	// --capability) should see the usage error, not a store-open
	// or rule-parse error.
	strictHostKeys, err := resolveStrictHostKeys(fs)
	if err != nil {
		return err
	}
	capOverrides, err := resolveCapabilityOverrides(capabilities)
	if err != nil {
		return &UsageError{Cause: err}
	}
	resolvedSeverities, err := validateSeverities(severities)
	if err != nil {
		return &UsageError{Cause: err}
	}
	normalizedTags := normalizeTags(tags)

	// Resolve variable substitution before rule load.
	// Remediate is single-host today, so the full 5-tier chain
	// (defaults + conf.d + groups (empty) + hosts/<host>.yml + CLI)
	// applies via ResolveTiers.
	cliVars, err := resolveVarOverrides(varOverrides)
	if err != nil {
		return &UsageError{Cause: err}
	}
	configDir = resolveConfigDir(configDir)
	loadVars, err := varsub.ResolveTiers(configDir, host, nil, cliVars)
	if err != nil {
		return WrapUsageError("--config-dir", err)
	}

	// C-037: --rule + positional args combine into the strict-load file set.
	rules, err := loadRulesFromDirOrFiles(rulesDir, concatPaths(ruleFiles, fs.Args()), loadVars)
	if err != nil {
		return err
	}
	// C-033: validate framework against pre-filter corpus snapshot.
	loadedFrameworks := availableFrameworks(rules)
	canonicalFramework, err := validateFramework(framework, loadedFrameworks)
	if err != nil {
		return &UsageError{Cause: err}
	}
	// C-035: parse + validate --control against pre-filter corpus.
	controlFilters, err := parseControlFilters(controls)
	if err != nil {
		return &UsageError{Cause: err}
	}
	if err := validateControls(controlFilters, rules); err != nil {
		return &UsageError{Cause: err}
	}
	rules = filterRulesBySeverity(rules, resolvedSeverities)
	if len(resolvedSeverities) > 0 && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--severity %v: no rules matched; nothing to remediate", resolvedSeverities))
	}
	preTagCount := len(rules)
	rules = filterRulesByTag(rules, normalizedTags)
	if len(normalizedTags) > 0 && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--tag %v: no rules matched (after --severity filter, %d rule(s) remained; none had matching tags)", normalizedTags, preTagCount))
	}
	preCategoryCount := len(rules)
	rules = filterRulesByCategory(rules, category)
	if category != "" && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--category %q: no rules matched (after upstream filters, %d rule(s) remained; none had matching category)", category, preCategoryCount))
	}
	preFrameworkCount := len(rules)
	rules = filterRulesByFramework(rules, canonicalFramework)
	if canonicalFramework != "" && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--framework %q: no rules matched (after upstream filters, %d rule(s) remained; none mapped this framework)", framework, preFrameworkCount))
	}
	preControlCount := len(rules)
	rules = filterRulesByControl(rules, controlFilters)
	if len(controlFilters) > 0 && len(rules) == 0 {
		return NewUsageError(fmt.Sprintf("--control %v: no rules matched (after upstream filters, %d rule(s) remained; none mapped any of these controls)", controls, preControlCount))
	}

	resolvedPwd, err := resolvePassword(password, os.Stdin, os.Stderr)
	if err != nil {
		return &UsageError{Cause: err}
	}
	resolvedSudoPwd, err := resolveSudoPasswordFor(fs, sudoPassword, sudo, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath,
		Password: resolvedPwd, StrictHostKeys: strictHostKeys, Sudo: sudo,
		SudoPassword: resolvedSudoPwd,
		Capabilities: capOverrides,
	}

	// Agent-mode safety: the agent is spawned via `sudo` over ssh and
	// its stdin carries the wire protocol. Feeding a sudo password to a
	// host that DOESN'T need one is unsafe — on a NOPASSWD host `sudo -S`
	// does not consume the stdin line, so it would corrupt the protocol.
	// Probe once and drop the password when the host is NOPASSWD, so the
	// password is fed (over ssh stdin) only to hosts that actually
	// require it. Applies to every downstream transport (bootstrap,
	// agent spawn, engine SSH path) since they all read hostCfg.
	if hostCfg.SudoPassword != "" && !sudoRequiresPassword(ctx, hostCfg) {
		fmt.Fprintln(os.Stderr, "kensa: host accepts passwordless sudo; ignoring --sudo-password (using sudo -n)")
		hostCfg.SudoPassword = ""
	}

	// L-014b + P-011: `kensa remediate` dispatches through
	// `kensa agent --stdio` on the target by default. Operators
	// can opt OUT of agent-mode by setting `KENSA_NO_AGENT=1`,
	// which falls back to the direct-SSH transport (shell-
	// pipeline best-effort atomicity for the file mechanisms).
	// Strict "1" match avoids false positives on misset values.
	//
	// Sense reversed 2026-05-12 per Q1.c ratification: kensa
	// is pre-production; the cleaner default is agent-mode.
	// Direct-SSH stays available for environments where agent
	// bootstrap isn't viable (noexec /tmp, restricted SSH user,
	// etc.) but no longer the default.
	//
	// Operability (F-007): atomic file operations
	// for file_content/file_absent/config_set/config_set_dropin
	// require agent-mode. Disclose the basis to operators on
	// stderr so audits don't claim atomicity that isn't being
	// delivered.
	var engineOpts []engine.Option
	useAgent := os.Getenv("KENSA_NO_AGENT") != "1"
	if useAgent {
		fmt.Fprintln(os.Stderr, "kensa: agent mode (default) — file_content/file_absent/config_set/config_set_dropin run with kernel-atomic primitives (O_TMPFILE + renameat2)")
	} else {
		fmt.Fprintln(os.Stderr, "kensa: direct-SSH mode (KENSA_NO_AGENT=1) — file mechanisms use shell-pipeline best-effort atomicity. Unset KENSA_NO_AGENT for kernel-atomic file operations.")
	}
	if useAgent {
		// Build the bootstrap SSH transport — same hostCfg
		// as the remediate path would use.
		bootstrapTransport, err := ssh.Factory{}.Connect(ctx, hostCfg)
		if err != nil {
			return fmt.Errorf("agent mode: connect to host for bootstrap: %w", err)
		}
		defer func() { _ = bootstrapTransport.Close() }()

		agentClient, cleanup, err := dispatcher.OpenAgent(ctx, bootstrapTransport, host, dispatcher.Options{
			User:         user,
			Sudo:         hostCfg.Sudo,
			SudoPassword: hostCfg.SudoPassword,
			Stderr:       os.Stderr,
		})
		if err != nil {
			return fmt.Errorf("agent mode: %w", err)
		}
		defer cleanup()
		engineOpts = append(engineOpts, engine.WithAgentClient(agentClient))
	}

	svc, err := kensa.DefaultWithEngineOptions(ctx, dbPath, engineOpts...)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()

	resolved := resolveAndPrintIssues(rules, quiet)

	// Default human path (text/table, no -o) streams result rows live —
	// one row per rule as each remediation completes (PASS = already
	// compliant, FIXED = remediated, FAIL = fix failed, ERROR), matching
	// `kensa check`. Machine formats / -o sinks stay buffered/structured.
	streamText := len(outputs) == 0 && (format == "text" || format == "table" || format == "")

	var result *api.RemediationResult
	if streamText {
		sw := output.NewStreamScanWriter(bodyOut(quiet), stdoutIsTerminal() && !quiet, resolved.Order)
		if !quiet {
			sw.Banner(host, "")
		}
		result, err = svc.RemediateWithProgress(ctx, hostCfg, resolved.Order, sw)
		if err != nil {
			return err
		}
		if !quiet {
			sw.Summary()
		}
	} else {
		result, err = svc.Remediate(ctx, hostCfg, resolved.Order)
		if err != nil {
			return err
		}
		if len(outputs) > 0 {
			specs, perr := output.ParseAll(outputs)
			if perr != nil {
				return WrapUsageError("--output", perr)
			}
			if err := routeFanOutError(output.FanOutRemediationResult(specs, bodyOut(quiet), host, resolved.Order, result)); err != nil {
				return err
			}
		} else if err := output.RemediationWriterOrText(format).WriteRemediationResult(bodyOut(quiet), host, resolved.Order, result); err != nil {
			return err
		}
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

%s

Examples:
  kensa remediate -H 192.168.1.211 -u owadmin --sudo -r /path/to/rules
  kensa remediate -H 192.168.1.211 -s critical -t pci -r /path/to/rules
  kensa remediate -H 192.168.1.211 -f cis-rhel9 --control cis_rhel9:5.1.12 -r /path/to/rules
  kensa remediate -H web-01 -u admin --sudo -o json -o oscal:/tmp/results.oscal.json
`, formatGroupedUsages(fs, remediateFlagGroups))
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

// runRollback dispatches across the four C-049 modes
// (--list, --info, --start, legacy --txn) plus --help.
// Each mode lives in cmd/kensa/rollback_session.go; this
// function only does flag parsing and mode mux.
func runRollback(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "user": true, "port": true, "key": true,
		"sudo": true, "txn": true, "list": true, "info": true,
		"start": true, "detail": true, "format": true,
	})

	fs := pflag.NewFlagSet("rollback", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		// Mode flags (C-049):
		listMode  bool
		infoSpec  string
		startSpec string
		detail    bool
		// Legacy --txn UUID (preserved):
		txnIDStr string
		// Target/transport flags (used by --start and --txn):
		host         string
		user         string
		port         int
		keyPath      string
		sudo         bool
		sudoPassword string
		// Output:
		format string
		quiet  bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.BoolVar(&listMode, "list", false, "list rollback-able sessions")
	fs.StringVar(&infoSpec, "info", "", "show detail for SESSION_ID (txns + statuses)")
	fs.StringVar(&startSpec, "start", "", "execute rollback for every committed txn in SESSION_ID")
	fs.BoolVar(&detail, "detail", false, "include per-step breakdown (composes with --list / --info)")
	fs.StringVarP(&txnIDStr, "txn", ShortTransaction, "", "legacy: roll back a single transaction by UUID")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required for --start and --txn)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	registerStrictHostKeysFlag(fs)
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	registerSudoPasswordFlag(fs, &sudoPassword)
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
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

	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}

	// Mode mux. Pick exactly one of the four mode selectors.
	var modes []string
	if listMode {
		modes = append(modes, "--list")
	}
	if infoSpec != "" {
		modes = append(modes, "--info")
	}
	if startSpec != "" {
		modes = append(modes, "--start")
	}
	if txnIDStr != "" {
		modes = append(modes, "--txn")
	}
	if len(modes) > 1 {
		return NewUsageError(fmt.Sprintf(
			"%s: pick exactly one rollback mode", strings.Join(modes, ", ")))
	}
	if len(modes) == 0 {
		return NewUsageError("specify a mode: --list, --info SESSION_ID, --start SESSION_ID, or legacy --txn TXN_UUID")
	}
	// --detail is a render modifier — composes with --list and
	// --info but not the executing modes.
	if detail && (startSpec != "" || txnIDStr != "") {
		return NewUsageError("--detail is a render modifier; it doesn't compose with --start or --txn (the executing modes)")
	}

	switch {
	case listMode:
		return runRollbackList(ctx, dbPath, detail, format, quiet)
	case infoSpec != "":
		sessID, err := uuid.Parse(infoSpec)
		if err != nil {
			return WrapUsageError(fmt.Sprintf("--info %q", infoSpec), err)
		}
		return runRollbackInfo(ctx, dbPath, sessID, detail, format, quiet)
	case startSpec != "":
		sessID, err := uuid.Parse(startSpec)
		if err != nil {
			return WrapUsageError(fmt.Sprintf("--start %q", startSpec), err)
		}
		hostCfg, err := buildRollbackHostCfg(fs, host, user, port, keyPath, sudo, sudoPassword)
		if err != nil {
			return err
		}
		return runRollbackStart(ctx, dbPath, sessID, hostCfg, format, quiet)
	}

	// Legacy --txn path.
	txnID, err := uuid.Parse(txnIDStr)
	if err != nil {
		return WrapUsageError("invalid --txn UUID", err)
	}
	hostCfg, err := buildRollbackHostCfg(fs, host, user, port, keyPath, sudo, sudoPassword)
	if err != nil {
		return err
	}
	svc, err := kensa.Default(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = svc.Close() }()
	result, err := svc.Rollback(ctx, hostCfg, txnID)
	if err != nil {
		return err
	}
	jw, _ := output.JSONValueWriterFor("json")
	return jw.WriteJSONValue(bodyOut(quiet), result)
}

// buildRollbackHostCfg validates --host / strict-host-keys
// and returns the api.HostConfig for the executing modes
// (--start and legacy --txn). --host is REQUIRED for both.
func buildRollbackHostCfg(fs *pflag.FlagSet, host, user string, port int, keyPath string, sudo bool, sudoPassword string) (api.HostConfig, error) {
	if host == "" {
		return api.HostConfig{}, NewUsageError("--host is required for rollback execution")
	}
	strictHostKeys, err := resolveStrictHostKeys(fs)
	if err != nil {
		return api.HostConfig{}, err
	}
	if sudoPassword != "" && !sudo {
		return api.HostConfig{}, NewUsageError("--sudo-password requires --sudo")
	}
	return api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath,
		StrictHostKeys: strictHostKeys, Sudo: sudo, SudoPassword: sudoPassword,
	}, nil
}

// printRollbackUsage writes the `kensa rollback` help text to w.
func printRollbackUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa rollback [MODE] [flags]

Roll back transactions using captured pre-state. Pick ONE mode:

  --list                  list rollback-able sessions (read-only)
  --info SESSION_ID       show session detail (txns + statuses)
  --start SESSION_ID      execute rollback for every committed
                          transaction in the session (needs --host)
  --txn TXN_UUID          legacy: single-transaction rollback (needs --host)

  --detail                modifier: per-step breakdown (composes with
                          --list and --info; not --start or --txn)

To find session UUIDs first, run:

  kensa list sessions

%s

Examples:
  kensa rollback --list
  kensa rollback --info 8c3a1e2b-... --detail
  kensa rollback --start 8c3a1e2b-... -H 192.168.1.211 -u owadmin --sudo
  kensa rollback --txn 9d4b... -H 192.168.1.211 -u owadmin --sudo  # legacy
`, formatGroupedUsages(fs, rollbackFlagGroups))
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
		stats     bool
		pruneDays int
		force     bool
		quiet     bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&hostID, "host", ShortHost, "", "filter by host ID")
	fs.StringVarP(&ruleID, "rule", ShortRule, "", "filter by rule ID")
	fs.StringVarP(&since, "since", ShortSince, "", "filter since duration (e.g. 24h) or RFC3339 time")
	fs.IntVarP(&limit, "limit", ShortLimit, 50, "maximum rows to return")
	fs.StringVarP(&format, "format", ShortFormat, "table", "output format: table, json, or jsonl (jsonl is transaction-list only)")
	fs.StringVarP(&txnIDStr, "txn", ShortTransaction, "", "get a single transaction by UUID")
	fs.StringVarP(&aggregate, "aggregate", ShortAggregate, "", "aggregate key: by_host, by_rule, by_framework_control")
	fs.BoolVar(&stats, "stats", false, "print summary stats (sessions, transactions, by status / severity / host) and exit")
	fs.IntVar(&pruneDays, "prune", 0, "delete sessions and cascade older than N days (destructive; long-only)")
	fs.BoolVar(&force, "force", false, "skip the confirmation prompt for --prune (required in non-interactive runs)")
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

	// C-043 --prune: destructive cleanup. Mutually exclusive
	// with every query-flag in this subcommand — combining
	// --prune with a query flag (--stats, --aggregate, --txn,
	// --host, --rule, --since, --limit, --format) almost
	// certainly means the operator confused two distinct
	// workflows. Fail-fast prevents accidental runs.
	if fs.Changed("prune") {
		if stats || aggregate != "" || txnIDStr != "" ||
			hostID != "" || ruleID != "" || since != "" ||
			fs.Changed("limit") || fs.Changed("format") {
			return NewUsageError("--prune is not compatible with --stats / --aggregate / --txn / --host / --rule / --since / --limit / --format")
		}
		return runHistoryPrune(ctx, dbPath, pruneDays, force, quiet, os.Stdin, bodyOut(quiet), os.Stderr)
	}
	if force {
		// --force without --prune has no effect; surface the
		// likely operator-confused intent rather than silently
		// ignoring the flag. (The earlier branch returned, so
		// reaching here means --prune was NOT set.)
		return NewUsageError("--force only applies to --prune")
	}

	// C-051: --format jsonl is for the transaction-list path
	// only. --aggregate / --stats / --txn UUID emit single
	// documents (host-keyed map, stats struct, single record);
	// jsonl-encoding a document is shape-violation. Reject
	// up front with a pointer at --format json.
	if format == "jsonl" && (aggregate != "" || stats || txnIDStr != "") {
		return NewUsageError(
			"--format jsonl is for the transaction listing only; --aggregate, --stats, and --txn emit single documents — use --format json for those")
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

	// C-042 --stats: aggregate session/transaction counts
	// scoped by the same host / since filters as a regular
	// history query. Uses the *SQLite ComputeStats path (the
	// LogQuery interface doesn't expose stats yet — and
	// kensa.Default returns the SQLite store as the log
	// concretely). For consistency with the rest of the
	// subcommand, we open a parallel sqlite handle just for
	// the stats query.
	if stats {
		s, err := store.OpenSQLite(ctx, dbPath)
		if err != nil {
			return fmt.Errorf("open store for stats: %w", err)
		}
		defer func() { _ = s.Close() }()
		st, err := s.ComputeStats(ctx, store.StatsFilter{
			Host:          hostID,
			Since:         filter.Since,
			TopHostsLimit: 10, // operator-friendly default; future flag could expose
		})
		if err != nil {
			return fmt.Errorf("stats: %w", err)
		}
		if format == "json" {
			return jsonValue.WriteJSONValue(out, st)
		}
		writeHistoryStatsText(out, st, hostID, since)
		return nil
	}

	result, err := log.Query(ctx, filter, api.Page{Limit: limit})
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	if format == "json" {
		return jsonValue.WriteJSONValue(out, result)
	}
	if format == "jsonl" {
		// C-051: one COMPACT JSON object per line — no
		// SetIndent. JSONValueWriter pretty-prints with two-
		// space indent; that's wrong for jsonl where each
		// object must occupy exactly one line. Use
		// json.NewEncoder directly: Encode writes one value
		// followed by a newline, no indentation.
		enc := json.NewEncoder(out)
		for _, tx := range result.Transactions {
			if err := enc.Encode(tx); err != nil {
				return err
			}
		}
		// Pagination trailer goes to stderr under jsonl
		// (matches csv convention: stdout is a row stream
		// consumed line-by-line).
		fmt.Fprintf(os.Stderr, "%d of %d transactions shown\n", len(result.Transactions), result.Total)
		return nil
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
  kensa history -n 200 --format json             # last 200 as JSON array
  kensa history -n 200 --format jsonl | jq -c .  # last 200 as JSON Lines (streamable to log aggregators)
  kensa history -H 192.168.1.211 -S 24h          # one host, last 24h
  kensa history -T 8c3a1e2b-...                  # one transaction by UUID
  kensa history -a by_host -S 7d                 # 7-day posture per host
  kensa history --prune 30                       # interactive prompt; deletes sessions older than 30 days
  kensa history --prune 30 --force               # non-interactive (CI / cron); skips the prompt
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
		showHelp     bool
		host         string
		user         string
		port         int
		keyPath      string
		password     string
		sudo         bool
		sudoPassword string
		format       string
		quiet        bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "target hostname (required)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVarP(&keyPath, "key", ShortKey, "", "SSH private key path")
	registerPasswordFlag(fs, &password)
	registerStrictHostKeysFlag(fs)
	fs.BoolVarP(&sudo, "sudo", ShortSudo, false, "wrap commands in sudo")
	registerSudoPasswordFlag(fs, &sudoPassword)
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

	// Flag-only constraint up front, before parsing the rule and
	// opening the store.
	strictHostKeys, err := resolveStrictHostKeys(fs)
	if err != nil {
		return err
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

	resolvedPwd, err := resolvePassword(password, os.Stdin, os.Stderr)
	if err != nil {
		return &UsageError{Cause: err}
	}
	resolvedSudoPwd, err := resolveSudoPasswordFor(fs, sudoPassword, sudo, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}

	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath,
		Password: resolvedPwd, StrictHostKeys: strictHostKeys, Sudo: sudo,
		SudoPassword: resolvedSudoPwd,
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

// ─── mechanisms (formerly: coverage) ───────────────────────────────────────

// runMechanisms lists all registered handler mechanisms.
//
// C-044 renamed this from `coverage` → `mechanisms`. The
// `coverage` name is preserved as a deprecated alias for one
// minor version; the wrapper at the dispatch site (case
// "coverage") emits a stderr warning before delegating here.
// `coverage` will be repurposed in C-045 for framework control
// coverage reporting (Python kensa's coverage semantics).
//
// The `name` argument is "mechanisms" or "coverage" depending
// on which alias the operator typed; help text and parse-error
// hints use it so they read coherently regardless of entry
// point.
func runMechanisms(name string, args []string) error {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var showHelp bool
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printMechanismsUsage(os.Stdout, fs, name)
			return nil
		}
		return WrapUsageError(fmt.Sprintf("try 'kensa %s --help'", name), err)
	}
	if showHelp {
		printMechanismsUsage(os.Stdout, fs, name)
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

	fmt.Printf("kensa %s (kensa)\n", version)
	return nil
}

// printVersionUsage writes the `kensa version` help text to w.
func printVersionUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa version

Print the kensa binary version. The top-level '--version' flag is
the canonical GNU/POSIX form; this subcommand is preserved for
backward compatibility and is planned for removal in v0.2.

Flags:
%s`, fs.FlagUsages())
}

// printMechanismsUsage writes the help text. The `name` parameter
// is "mechanisms" (canonical) or "coverage" (alias under
// repurpose); it's used in the Usage line, the example, and the
// repurpose disclosure so help reads coherently regardless of
// entry point. When invoked as `coverage`, the WARNING block
// prints BEFORE the flag list — operators reading help to
// write a script need to see the v0.2 semantic flip first.
func printMechanismsUsage(w io.Writer, fs *pflag.FlagSet, name string) {
	fmt.Fprintf(w, "Usage: kensa %s [flags]\n\n", name)
	if name == "coverage" {
		fmt.Fprint(w,
			"WARNING: 'kensa coverage' will change meaning in v0.2.\n"+
				"  Today: lists handler mechanisms (alias for 'kensa mechanisms').\n"+
				"  v0.2:  reports framework control coverage.\n"+
				"Migrate scripts to 'kensa mechanisms' to preserve current output.\n\n"+
				"AVAILABLE TODAY: the v0.2 framework-coverage report is already\n"+
				"reachable via:\n"+
				"  kensa coverage --framework FRAMEWORK --rules-dir DIR\n"+
				"  kensa coverage --framework cis_rhel9 --help    # full report help\n\n")
	}
	fmt.Fprintf(w, `List every handler mechanism registered with the kensa engine,
marked capturable (participates in atomic transactions) or
non-capturable (transactional: false escape hatch).

Flags:
%s
Example:
  kensa %s
`, fs.FlagUsages(), name)
}

// ─── helpers ───────────────────────────────────────────────────────────────

// loadRules parses a set of rule YAML files into []*api.Rule.
// Phase 3.5: when vars is non-nil, `{{ name }}` templates in
// each YAML are substituted before decoding; an undefined
// variable produces a parse error.
func loadRules(paths []string, vars varsub.Variables) ([]*api.Rule, error) {
	rules := make([]*api.Rule, 0, len(paths))
	for _, p := range paths {
		r, err := rule.ParseFileWithVars(p, vars)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// loadRulesFromDirOrFiles loads rules from a directory (if dir != "")
// AND/OR from the explicit file paths. Pre-C-037 the two were
// mutually exclusive; post-C-037 they're additive — operators can
// pass --rules-dir for the bulk corpus and --rule for one-off
// additions, or pass --rule alone (matches the positional rule-file
// arg form). Returns an error when both are empty.
//
// Directory walks use loadRulesSkipInvalid (warn-and-skip on parse
// error) because corpora often contain in-progress drafts; explicit
// file paths use the strict loader because the operator named the
// file deliberately and a parse failure should surface, not be
// silently dropped.
// rulesStat is the stat function used by loadRulesFromDirOrFiles to detect
// the kensa-rules package's default install path. Production uses os.Stat;
// tests override it to make the default-path fallback deterministic
// regardless of what's on the test host's filesystem.
var rulesStat = os.Stat

func loadRulesFromDirOrFiles(dir string, paths []string, vars varsub.Variables) ([]*api.Rule, error) {
	// Resolve the effective rules directory before walking: explicit
	// --rules-dir wins, positional paths alone skip the walk, otherwise
	// fall back to the kensa-rules package's installed corpus at
	// rulespath.DefaultPath when present, otherwise return a usage
	// error naming both fix paths. See specs/rule/default-path-resolution.
	resolved, err := rulespath.Resolve(dir, paths, rulesStat)
	if err != nil {
		return nil, NewUsageError(err.Error())
	}
	dir = resolved

	var rules []*api.Rule
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
		if len(found) == 0 && len(paths) == 0 {
			return nil, fmt.Errorf("no *.yml files found in %s", dir)
		}
		dirRules, err := loadRulesSkipInvalid(found, vars)
		if err != nil {
			return nil, err
		}
		rules = append(rules, dirRules...)
	}
	if len(paths) > 0 {
		fileRules, err := loadRules(paths, vars)
		if err != nil {
			return nil, err
		}
		rules = append(rules, fileRules...)
	}
	if len(rules) == 0 {
		return nil, NewUsageError("at least one rule YAML file or --rules-dir is required")
	}
	return rules, nil
}

// loadRulesSkipInvalid loads rules, printing a warning and skipping files
// that fail to parse rather than aborting the whole load. Phase 3.5:
// undefined-variable errors are recognized via varsub.ErrUndefined and
// aggregated into an end-of-load summary so an operator running against
// the corpus without --var sees the missing-variable scope clearly,
// not buried in 30 individual warnings. Other parse errors keep the
// per-file warn-and-skip behavior (corpora often contain in-progress
// drafts; one broken YAML shouldn't abort the whole scan).
func loadRulesSkipInvalid(paths []string, vars varsub.Variables) ([]*api.Rule, error) {
	rules := make([]*api.Rule, 0, len(paths))
	var undefined []string
	for _, p := range paths {
		r, err := rule.ParseFileWithVars(p, vars)
		if err != nil {
			if errors.Is(err, varsub.ErrUndefined) {
				undefined = append(undefined, fmt.Sprintf("%s: %v", p, err))
				continue
			}
			fmt.Fprintf(os.Stderr, "warn: skip %s: %v\n", p, err)
			continue
		}
		rules = append(rules, r)
	}
	if len(undefined) > 0 {
		fmt.Fprintf(os.Stderr,
			"warn: %d rule(s) skipped — undefined variables. Define them via --var KEY=VALUE or in <config-dir>/defaults.yml. First few:\n",
			len(undefined))
		limit := 5
		if len(undefined) < limit {
			limit = len(undefined)
		}
		for i := 0; i < limit; i++ {
			fmt.Fprintf(os.Stderr, "  - %s\n", undefined[i])
		}
		if len(undefined) > limit {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(undefined)-limit)
		}
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
