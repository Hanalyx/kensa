package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa-go/internal/output"
	"github.com/Hanalyx/kensa-go/internal/store"
)

// runListSessions handles `kensa list sessions [flags]` (C-048).
// Surfaces session IDs from the transaction store so operators
// can pick UUIDs for `kensa diff`. Without this, the diff
// command was effectively undiscoverable — peer review caught
// the gap.
func runListSessions(ctx context.Context, dbPath string, args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"host": true, "limit": true, "format": true,
	})

	fs := pflag.NewFlagSet("list sessions", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		hostname string
		limit    int
		format   string
		quiet    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&hostname, "host", ShortHost, "", "filter by hostname (denormalized session.hostname column)")
	fs.IntVarP(&limit, "limit", ShortLimit, 20, "maximum sessions to show (0 = unlimited)")
	fs.StringVarP(&format, "format", ShortFormat, "text", "output format: text or json")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output (errors still go to stderr)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printListSessionsUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa list sessions --help'", err)
	}
	if showHelp {
		printListSessionsUsage(os.Stdout, fs)
		return nil
	}
	switch format {
	case "text", "json":
	default:
		return NewUsageError(fmt.Sprintf("--format %q: must be 'text' or 'json'", format))
	}
	if limit < 0 {
		return NewUsageError(fmt.Sprintf("--limit %d: must be ≥ 0", limit))
	}

	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	sessions, err := s.ListSessions(ctx, hostname, limit)
	if err != nil {
		return err
	}

	out := bodyOut(quiet)
	if format == "json" {
		jw, _ := output.JSONValueWriterFor("json")
		envelope := struct {
			Sessions []sessionRow `json:"sessions"`
		}{Sessions: toSessionRows(sessions)}
		return jw.WriteJSONValue(out, envelope)
	}
	writeListSessionsText(out, sessions)
	return nil
}

// sessionRow is the JSON-shape row for `list sessions`. Snake
// case for parity with the rest of kensa-go's API surface.
// Mirrors store.Session but with operator-relevant fields and
// stable JSON tags (the store.Session shape carries internal
// timestamps in time.Time, which JSON-encode as RFC3339).
type sessionRow struct {
	ID            string `json:"id"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	Hostname      string `json:"hostname"`
	Subcommand    string `json:"subcommand"`
	TxnTotal      int    `json:"txn_total"`
	TxnCommitted  int    `json:"txn_committed"`
	TxnRolledBack int    `json:"txn_rolled_back"`
}

func toSessionRows(sessions []*store.Session) []sessionRow {
	out := make([]sessionRow, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionRow{
			ID:            s.ID.String(),
			StartedAt:     s.StartedAt.UTC().Format(time.RFC3339),
			FinishedAt:    s.FinishedAt.UTC().Format(time.RFC3339),
			Hostname:      s.Hostname,
			Subcommand:    s.Subcommand,
			TxnTotal:      s.TxnTotal,
			TxnCommitted:  s.TxnCommitted,
			TxnRolledBack: s.TxnRolled,
		})
	}
	return out
}

func writeListSessionsText(w io.Writer, sessions []*store.Session) {
	fmt.Fprintln(w, "kensa list sessions")
	if len(sessions) == 0 {
		fmt.Fprintln(w, "  (no sessions in the store)")
		return
	}
	fmt.Fprintf(w, "  %d session(s)\n\n", len(sessions))
	fmt.Fprintln(w, "  started_at            hostname           subcmd     committed/total  session_id")
	fmt.Fprintln(w, "  --------------------  -----------------  ---------  ---------------  ------------------------------------")
	for _, s := range sessions {
		host := s.Hostname
		if host == "" {
			host = "(unknown)"
		}
		fmt.Fprintf(w, "  %-20s  %-17s  %-9s  %3d / %-9d  %s\n",
			s.StartedAt.UTC().Format("2006-01-02 15:04:05"),
			host,
			s.Subcommand,
			s.TxnCommitted, s.TxnTotal,
			s.ID.String(),
		)
	}
}

func printListSessionsUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa list sessions [flags]

List recent sessions in the transaction store. The session_id
column is the UUID needed by 'kensa diff SESSION1 SESSION2'.

Flags:
%s
Examples:
  kensa list sessions                          # 20 most recent
  kensa list sessions -H 192.168.1.211         # one hostname
  kensa list sessions --format json -n 5       # last 5 as JSON
`, fs.FlagUsages())
}
