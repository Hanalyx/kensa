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
//	-v  → --verbose  (GNU convention; not yet used by kensa-go)
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
	//     `--dry-run` short (Phase 3 deliverables in
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

	// ShortPort is `--port`. SSH port.
	ShortPort = "p"

	// ShortKey is `--key`. SSH private key path.
	// Note: deviates from OpenSSH's `-i identity_file` because `-i`
	// is reserved system-wide for `--inventory` in `kensa check`,
	// and we keep one short-letter assignment per long flag across
	// the entire CLI for consistency.
	ShortKey = "k"

	// ShortSudo is `--sudo`. Wrap remote commands in sudo.
	ShortSudo = "s"

	// Output / format options.

	// ShortFormat is `--format`. Output format selector. CLI Phase 2
	// (C-019) introduced `-o, --output FORMAT[:PATH]` as the canonical
	// repeatable form for multi-target dispatch; --format remains
	// supported as the single-target shortcut and is deprecated for
	// removal in C-020 with one minor version of overlap.
	ShortFormat = "f"

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

	// ShortRule is `--rule` (filter by rule ID). Capital R because
	// lowercase `-r` is reserved for `--rules-dir` in target/rule
	// scope. Used in commands that filter the transaction log.
	ShortRule = "R"

	// ShortSince is `--since` (history filter). Capital S because
	// lowercase `-s` is reserved for `--sudo`.
	ShortSince = "S"

	// ShortLimit is `--limit` (max rows / max items). The head/tail
	// convention. (Note: in target_options scope where `--limit`
	// means a host glob — Phase 3 deliverable — `-l` is the planned
	// short form; the meanings don't conflict because the two flags
	// take different argument types.)
	ShortLimit = "n"

	// ShortTransaction is `--txn` (transaction UUID).
	ShortTransaction = "t"

	// ShortAggregate is `--aggregate` (history aggregation key).
	ShortAggregate = "a"

	// ShortQuiet is `--quiet`. Suppresses default human-readable
	// output to stdout. Errors and warnings still go to stderr;
	// exit codes are unchanged. Operators use --quiet in CI
	// scripts where only the exit code matters, or with `-o` (CLI
	// Phase 2) when they want the formatted output to land in a
	// file without a copy on stdout.
	ShortQuiet = "q"
)
