package main

import (
	"context"
	"fmt"
	"io"
	"os"
)

// runList is the C-046 sub-dispatcher for `kensa list <subject>`.
// Subjects are `frameworks`, `sessions` and `variables`. Future
// follow-ups (e.g. `list controls`, `list rules`) compose
// naturally without name collisions; the dispatcher stays
// thin so adding a subject is one switch arm + one new
// handler file.
//
// Exit-code contract:
//   - `kensa list --help` / `-h` → exit 0 (help is help)
//   - `kensa list` (no subject)  → exit 2 (usage error; CI-script footgun
//     prevention — peer review caught silent no-op risk)
//   - `kensa list <unknown>`     → exit 2 (usage error)
//   - `kensa list <-flag>`       → exit 2 with "did you forget the subject?"
//     hint (operator typed flags before the subject)
//
// runList needs the global dbPath for sub-subjects that hit
// the SQLite store (C-048: `list sessions`). Sub-subjects that
// only need a rule corpus (C-046: `list frameworks`) ignore it.
func runList(ctx context.Context, dbPath string, args []string) error {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		printListUsage(os.Stdout)
		return nil
	}
	if len(args) == 0 {
		printListUsage(os.Stderr)
		return NewUsageError("specify a subject; available: frameworks, sessions, variables")
	}
	subject := args[0]
	if subject != "" && subject[0] == '-' {
		// Several subjects take --rules-dir now, so guessing which one the
		// operator meant would be a coin flip. Name them all instead.
		return NewUsageError(fmt.Sprintf(
			"missing 'list' subject (got flag %q first); available: frameworks, sessions, variables",
			subject))
	}
	rest := args[1:]
	switch subject {
	case "frameworks":
		return runListFrameworks(ctx, rest)
	case "sessions":
		return runListSessions(ctx, dbPath, rest)
	case "variables":
		return runListVariables(rest)
	default:
		return NewUsageError(fmt.Sprintf("unknown 'list' subject %q; available: frameworks, sessions, variables", subject))
	}
}

func printListUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: kensa list <subject> [flags]

Introspection commands for the rule corpus and the transaction store.

Subjects:
  frameworks   Per-framework control + rule counts (requires --rules-dir DIR)
  sessions     List recent sessions in the transaction store (with IDs for `+"`kensa diff`"+`)
  variables    Rule variables the corpus references, with type and default (requires --rules-dir DIR)

Run "kensa list <subject> --help" for subject-specific flags.
`)
}
