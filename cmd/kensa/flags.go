// Centralized short-letter table for the kensa CLI (deliverable C-005
// in docs/roadmap/DELIVERABLES.md).
//
// Every short flag letter the kensa binary accepts is declared as a
// constant in this file. Adding a new short letter is a deliberate,
// reviewed action: a collision-detection test in flags_test.go fails
// the build if two constants share the same letter, surfacing the
// conflict at code-review time rather than at runtime.
//
// The table follows GNU/POSIX convention with three reservations that
// are sacred and never reused:
//
//	-h  → --help     (GNU convention)
//	-V  → --version  (GNU convention)
//	-v  → --verbose  (GNU convention; not yet used by kensa)
//
// The case discipline is intentional. Several short letters use the
// uppercase form because the lowercase form was already taken by a
// more-frequently-used flag in the same scope or by a sacred GNU
// reservation. The rationale is in
// docs/roadmap/CLI_GNU_POSIX_MIGRATION_V1.md §4.
//
// When a future deliverable introduces a new short flag, add the
// constant here and use it in the pflag registration. Don't pass
// raw string literals like "h" or "u" into BoolVarP / StringVarP —
// the centralization is the whole point.
package main

const (
	// Reserved (GNU/POSIX) — never reused for any other flag.

	// ShortHelp is the canonical short form for `--help`.
	// Reserved across every subcommand and the top-level binary.
	ShortHelp = "h"

	// ShortVersion is the canonical short form for `--version`.
	// Reserved at the top level only; subcommands do not register it.
	ShortVersion = "V"

	// ShortVerbose is the canonical short form for `--verbose`.
	// Reserved system-wide; not yet registered on any subcommand
	// (no command currently has a verbosity dimension worth
	// surfacing). When verbosity ships, it uses this letter.
	ShortVerbose = "v"

	// Top-level only.

	// ShortDb is `--db` (SQLite transaction-log path). Top-level only.
	// Uppercase D rather than lowercase d for two reasons:
	//  1. The legacy stdlib-flag form was `-db` (single-dash long); the
	//     uppercase D preserves recognizability for operators migrating
	//     from that form (`-D` looks adjacent to the legacy `-db`).
	//  2. Lowercase d is left unclaimed for a potential future
	//     `--dry-run` short (future deliverables in
	//     CLI_GNU_POSIX_MIGRATION_V1.md introduce `--dry-run` for
	//     remediate; if a short alias is later added, `-d` is the
	//     conventional choice).
	ShortDb = "D"

	// SSH connection / target options (used by detect, check,
	// remediate, rollback, plan).

	// ShortHost is `--host`. Capital H because lowercase `-h` is
	// reserved for `--help`. Deviation from Python kensa's `-h, --host`
	// (intentional; documented in CLI_GNU_POSIX_MIGRATION_V1.md §4.3).
	ShortHost = "H"

	// ShortUser is `--user`. SSH username.
	ShortUser = "u"

	// ShortPort is `--port`. SSH port. CAPITAL P per
	// CLI_GNU_POSIX_MIGRATION_V1.md §4.2; lowercase `-p` is reserved
	// for `--password` (wired in C-026). The C-024 reconciliation
	// flipped this from the original default; CHANGELOG.md notes
	// the breaking change.
	ShortPort = "P"

	// ShortKey is `--key`. SSH private key path.
	// Note: deviates from OpenSSH's `-i identity_file` because `-i`
	// is reserved system-wide for `--inventory` in `kensa check`,
	// and we keep one short-letter assignment per long flag across
	// the entire CLI for consistency.
	ShortKey = "k"

	// ShortSudo: --sudo has NO short letter. Per
	// CLI_GNU_POSIX_MIGRATION_V1.md §3.2, Python kensa's --sudo
	// also has no short. The C-024 reconciliation freed the
	// previous `-s` for `--severity` (C-030). The constant is
	// retained as the empty string so call sites that read
	// ShortSudo continue to compile and resolve to "no short".
	ShortSudo = ""

	// Output / format options.

	// ShortFormat: --format has NO short letter as of C-024.
	// Per CLI_GNU_POSIX_MIGRATION_V1.md §4.2, lowercase `-f` is
	// reserved for `--framework` (wired in C-033). The --format
	// long form remains as a deprecated alias (per C-020); it
	// will be removed in v0.2. Operators using `-f` for format
	// migrate to `-o FORMAT` or `--output FORMAT`. The constant
	// is retained as "" so call sites continue to compile.
	ShortFormat = ""

	// ShortOutput is `--output FORMAT[:PATH]`, repeatable. Each value
	// is one Spec parsed by internal/output.Parse (e.g., "json",
	// "csv:results.csv", "oscal:/tmp/asmt.json"). Multiple `-o`
	// invocations fan out concurrently across all specs against the
	// same in-memory result. Wired in C-019.
	ShortOutput = "o"

	// Rule selection / file paths.

	// ShortRulesDir is `--rules-dir`. Rules directory.
	ShortRulesDir = "r"

	// Filter / query options (used by history, info, rollback list).

	// ShortRule is `-R` (filter by rule ID, future deliverable).
	// Capital R because lowercase `-r` is reserved for `--rules-dir`.
	// NOTE: post-C-037, the long form `--rule` is bound to the
	// file-loading semantic (load this single rule YAML file). When
	// the filter-by-ID feature lands, it must pick a different long
	// name (e.g. `--rule-id` or `--filter-id`); the `-R` short can
	// stay reserved for that flag. Until then, this constant has no
	// active binding.
	ShortRule = "R"

	// ShortSince is `--since` (history filter). Capital S because
	// lowercase `-s` is reserved for `--sudo`.
	ShortSince = "S"

	// ShortLimit is `--limit` (max rows / max items). The head/tail
	// convention. (Note: in target_options scope where `--limit`
	// means a host glob — a future deliverable — `-l` is the planned
	// short form; the meanings don't conflict because the two flags
	// take different argument types.)
	ShortLimit = "n"

	// ShortTransaction is `--txn` (transaction UUID). CAPITAL T
	// per the C-024 reconciliation; lowercase `-t` is reserved for
	// `--tag` (wired in C-031). Used by `kensa rollback` and the
	// `kensa history --txn` filter.
	ShortTransaction = "T"

	// ShortAggregate is `--aggregate` (history aggregation key).
	ShortAggregate = "a"

	// ShortQuiet is `--quiet`. Suppresses default human-readable
	// output to stdout. Errors and warnings still go to stderr;
	// exit codes are unchanged. Operators use --quiet in CI
	// scripts where only the exit code matters, or with `-o` when they want the formatted output to land in a
	// file without a copy on stdout.
	ShortQuiet = "q"

	// ShortInventory is `--inventory` (Ansible-style inventory.ini
	// for multi-host runs). Wired in C-023; the long form has been
	// supported since the first release.
	ShortInventory = "i"

	// Placeholder short letters reserved for future flags. The constants are
	// declared here (in the centralized table) so the collision
	// checker and case-discipline tests cover them; the actual flag
	// wiring lands in the named deliverable. Until then, attempting
	// to use these short letters produces "unknown shorthand".

	// ShortPassword is `--password` (SSH password auth, with
	// secure prompt when no value given). Wired in C-026.
	ShortPassword = "p"

	// ShortLimitGlob is `--limit` (host glob filter for inventory
	// mode, ansible --limit semantics). Wired in C-025. Note: the
	// existing ShortLimit ("n") for --limit row-count in
	// history/rollback is a SEPARATE flag in a different scope;
	// the migration doc accepts the lowercase-l vs lowercase-n
	// reuse because the two flags take different argument types.
	// Constant is named ShortLimitGlob (not ShortLimit) to keep
	// godoc unambiguous about which scope it belongs to.
	ShortLimitGlob = "l"

	// ShortSeverity is `--severity` (rule filter: critical/high/
	// medium/low). Wired in C-030. Lowercase `-s` was freed by
	// the --sudo reconciliation in C-024.
	ShortSeverity = "s"

	// ShortTag is `--tag` (rule filter, repeatable). Wired in C-031.
	// Lowercase `-t` was freed by the --txn → -T reconciliation.
	ShortTag = "t"

	// ShortCategory is `--category` (rule filter). Wired in C-032.
	ShortCategory = "c"

	// ShortFramework is `--framework` (filter to rules in a
	// framework mapping). Wired in C-033. Lowercase `-f` was freed
	// by the --format reconciliation; the --format long form
	// remains as a deprecated alias.
	ShortFramework = "f"

	// ShortCapability is `--capability` (capability override,
	// repeatable). Wired in C-028. Capital C — operators rarely
	// use it interactively, and lowercase c is --category.
	ShortCapability = "C"

	// ShortWorkers is `--workers` (parallel SSH connections, 1-50).
	// Wired in C-029.
	ShortWorkers = "w"

	// ShortVar is `--var` (rule-variable override KEY=VALUE,
	// repeatable). Wired in C-034. Lowercase x — Python kensa
	// uses -V which is reserved for --version in kensa;
	// `-x` mnemonic is "eXtra var" matching ansible's `-e`.
	ShortVar = "x"
)
