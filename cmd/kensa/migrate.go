package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/internal/store"
)

// runMigrate applies pending schema migrations to the SQLite
// store and backfills synthetic sessions for pre-Phase-4
// transactions. Idempotent: a second run on an already-
// migrated DB applies no migration and finds no NULL session
// rows, exiting 0 with a "no work" report.
//
// Phase 4 / C-040. The schema migrations themselves run
// automatically on every OpenSQLite call (Phase 1 design); the
// `kensa migrate` subcommand exists primarily to:
//  1. Surface the schema version for operators auditing a DB.
//  2. Run the session backfill explicitly so operators
//     upgrading from pre-Phase-4 see a deterministic
//     one-time conversion they can script around.
func runMigrate(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"db": true, "quiet": true,
	})

	fs := pflag.NewFlagSet("migrate", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		quiet    bool
		dbFlag   string
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVar(&dbFlag, "db", "", "override the default store path")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress the migration summary (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printMigrateUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa migrate --help'", err)
	}
	if showHelp {
		printMigrateUsage(os.Stdout, fs)
		return nil
	}

	path := dbPath
	if dbFlag != "" {
		path = dbFlag
	}

	s, err := store.OpenSQLite(ctx, path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	report, err := s.BackfillSessions(ctx)
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}

	// bodyOut returns io.Discard when quiet is true; we don't
	// need a redundant outer guard.
	w := bodyOut(quiet)
	fmt.Fprintf(w, "kensa migrate: store at %s\n", path)
	fmt.Fprintf(w, "  schema version:        %d\n", report.SchemaVersion)
	fmt.Fprintf(w, "  sessions created:      %d (synthetic, subcommand=legacy-backfill)\n", report.SessionsCreated)
	fmt.Fprintf(w, "  transactions attached: %d\n", report.TransactionsAttached)
	if report.SessionsCreated == 0 {
		fmt.Fprintln(w, "  (already migrated; no work to do)")
	}
	return nil
}

func printMigrateUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa migrate [flags]

Apply pending schema migrations to the SQLite store and backfill
synthetic sessions for pre-Phase-4 transactions. Idempotent — a
second run finds no work and exits 0.

Pre-Phase-4 transactions (rows whose session_id is NULL because
they predate the C-039 session schema) are grouped one synthetic
session per host_id. The synthetic session's subcommand is
'legacy-backfill' so operators can distinguish it from real
CLI-invocation sessions in subsequent kensa history / kensa diff
runs.

Flags:
%s
Examples:
  kensa migrate
  kensa migrate --db /var/lib/kensa/results.db
  kensa migrate --quiet     # suppress summary; non-zero exit on error only
`, fs.FlagUsages())
}
