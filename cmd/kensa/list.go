package main

import (
	"context"
	"fmt"
	"io"
	"os"
)

// runList is the C-046 sub-dispatcher for `kensa list <subject>`.
// Today the only subject is `frameworks`. Future Phase 4
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
		return NewUsageError("specify a subject; available: frameworks, sessions")
	}
	subject := args[0]
	if subject != "" && subject[0] == '-' {
		return NewUsageError(fmt.Sprintf(
			"missing 'list' subject (got flag %q first); did you mean 'kensa list frameworks %s'?",
			subject, joinArgs(args)))
	}
	rest := args[1:]
	switch subject {
	case "frameworks":
		return runListFrameworks(ctx, rest)
	case "sessions":
		return runListSessions(ctx, dbPath, rest)
	default:
		return NewUsageError(fmt.Sprintf("unknown 'list' subject %q; available: frameworks, sessions", subject))
	}
}

// joinArgs returns args separated by a space, used in the
// forgotten-subject usage hint so the suggested rewrite reads
// like a copy-pastable command.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func printListUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: kensa list <subject> [flags]

Introspection commands for the rule corpus and the transaction store.

Subjects:
  frameworks   Per-framework control + rule counts (requires --rules-dir DIR)
  sessions     List recent sessions in the transaction store (with IDs for `+"`kensa diff`"+`)

Run "kensa list <subject> --help" for subject-specific flags.
`)
}
