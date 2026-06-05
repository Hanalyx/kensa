// Tests for the --progress=auto|always|never flag and the progress
// wiring on `kensa check` / `kensa detect` (PR4, spec cli-progress-stream).
//
// The decision logic (progressEnabled) is a pure function of three
// injected inputs, so the TTY heuristic is exercised deterministically
// without a real terminal. The sink-construction and result-invariance
// ACs are covered against in-package fakes; the SSH-dependent end-to-end
// path is out of scope (no transport mock at the dispatcher level).
package main

import (
	"bytes"
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
	"github.com/Hanalyx/kensa/internal/scan"
)

// progressFakeTransport satisfies api.Transport for the result-invariance
// test. Every probe and check command succeeds with empty output, which is
// enough to drive scan.ScanWithOverrides deterministically.
type progressFakeTransport struct{}

func (progressFakeTransport) Run(_ context.Context, _ string) (*api.CommandResult, error) {
	return &api.CommandResult{ExitCode: 0}, nil
}
func (progressFakeTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (progressFakeTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (progressFakeTransport) Close() error                                            { return nil }
func (progressFakeTransport) ControlChannelSensitive() bool                           { return false }

// TestProgressFlag_InHelp confirms --progress with its choices appears in
// both `kensa check --help` and `kensa detect --help`.
// @spec cli-progress-stream
// @ac AC-01
func TestProgressFlag_InHelp(t *testing.T) {
	t.Run("cli-progress-stream/AC-01", func(t *testing.T) {
		for _, cmd := range []string{"check", "detect"} {
			stdout, _ := captureRunCLI([]string{cmd, "--help"}, t)
			for _, tok := range []string{"--progress", "auto", "always", "never"} {
				if !strings.Contains(stdout, tok) {
					t.Errorf("kensa %s --help missing %q in --progress help; got:\n%s", cmd, tok, stdout)
				}
			}
		}
	})
}

// TestProgressEnabled_Matrix locks the pure decision function across the
// mode x TTY x quiet matrix. auto = tty && !quiet; always = on; never =
// off (regardless of TTY/quiet).
// @spec cli-progress-stream
// @ac AC-02
func TestProgressEnabled_Matrix(t *testing.T) {
	t.Run("cli-progress-stream/AC-02", func(t *testing.T) {
		cases := []struct {
			mode  string
			tty   bool
			quiet bool
			want  bool
		}{
			{progressAuto, true, false, true},    // interactive terminal, not quiet -> on
			{progressAuto, false, false, false},  // redirected stderr -> off
			{progressAlways, false, true, true},  // always overrides TTY heuristic and quiet
			{progressNever, true, false, false},  // never overrides the TTY heuristic
			{progressAlways, true, false, true},  // always at a TTY -> on
			{progressNever, false, false, false}, // never with no TTY -> off
		}
		for _, c := range cases {
			if got := progressEnabled(c.mode, c.tty, c.quiet); got != c.want {
				t.Errorf("progressEnabled(%q, tty=%v, quiet=%v) = %v, want %v",
					c.mode, c.tty, c.quiet, got, c.want)
			}
		}
	})
}

// TestProgressEnabled_QuietWinsInAuto pins the precedence rule: in auto
// mode --quiet suppresses progress even at an interactive terminal.
// @spec cli-progress-stream
// @ac AC-03
func TestProgressEnabled_QuietWinsInAuto(t *testing.T) {
	t.Run("cli-progress-stream/AC-03", func(t *testing.T) {
		if progressEnabled(progressAuto, true, true) {
			t.Error("progressEnabled(auto, tty=true, quiet=true) = true; --quiet must win in auto mode")
		}
		// Sanity: without --quiet the same TTY produces on, proving quiet
		// is the deciding input here, not the TTY.
		if !progressEnabled(progressAuto, true, false) {
			t.Error("progressEnabled(auto, tty=true, quiet=false) = false; want on")
		}
	})
}

// TestProgressMode_RejectsUnknown confirms an out-of-vocabulary --progress
// value is a usage error (exit 2) on both check and detect, surfaced before
// any transport dial (a bogus host that would fail to connect never matters
// because the flag is rejected first).
// @spec cli-progress-stream
// @ac AC-04
func TestProgressMode_RejectsUnknown(t *testing.T) {
	t.Run("cli-progress-stream/AC-04", func(t *testing.T) {
		// Direct helper contract.
		if err := validateProgressMode("sometimes"); err == nil {
			t.Fatal("validateProgressMode(\"sometimes\") = nil; want usage error")
		} else if !IsUsageError(err) {
			t.Errorf("validateProgressMode(\"sometimes\") err is not a UsageError: %v", err)
		}
		for _, mode := range []string{progressAuto, progressAlways, progressNever} {
			if err := validateProgressMode(mode); err != nil {
				t.Errorf("validateProgressMode(%q) = %v, want nil", mode, err)
			}
		}
		// End-to-end exit code on both commands. --host is supplied so the
		// rejection is the --progress mode, not a missing-host usage error;
		// the bad mode is rejected before any SSH connect is attempted.
		for _, cmd := range []string{"check", "detect"} {
			code := runCLI([]string{cmd, "--host", "127.0.0.1", "--progress", "bogus"})
			if code != 2 {
				t.Errorf("kensa %s --progress bogus exit = %d, want 2 (usage error)", cmd, code)
			}
		}
	})
}

// TestNewProgressSink_WritesOnlyToWriter confirms the sink the CLI wires
// renders Updates to the supplied (non-stdout) writer and never touches
// stdout. The renderer is captured in a bytes.Buffer; os.Stdout is never
// passed to newProgressSink.
// @spec cli-progress-stream
// @ac AC-05
func TestNewProgressSink_WritesOnlyToWriter(t *testing.T) {
	t.Run("cli-progress-stream/AC-05", func(t *testing.T) {
		var buf bytes.Buffer
		sink := newProgressSink(&buf, false)
		if sink == nil {
			t.Fatal("newProgressSink returned nil")
		}
		// It must satisfy progress.Sink so scan/detect can consume it.
		var _ progress.Sink = sink

		sink.Update(progress.Update{
			Kind: progress.RuleChecked, RuleID: "rule-x",
			Index: 1, Total: 3, OK: true,
		})
		if buf.Len() == 0 {
			t.Fatal("newProgressSink wrote nothing to the supplied writer")
		}
		if !strings.Contains(buf.String(), "rule-x") {
			t.Errorf("rendered line missing rule id; got: %q", buf.String())
		}
	})
}

// TestProgress_ResultInvariantOnVsOff confirms the canonical result is
// independent of progress state: scanning the same rules over the same
// transport with a progress sink wired (on) versus a nil sink (off) yields
// a deep-equal ScanResult. Progress is additive on the writer only and
// never alters the result that lands on stdout.
// @spec cli-progress-stream
// @ac AC-06
func TestProgress_ResultInvariantOnVsOff(t *testing.T) {
	t.Run("cli-progress-stream/AC-06", func(t *testing.T) {
		ctx := context.Background()
		rules := []*api.Rule{
			{ID: "r1", Severity: "high"},
			{ID: "r2", Severity: "low"},
		}
		tr := progressFakeTransport{}

		// OFF: nil sink, exactly the pre-PR4 construction.
		off, err := scan.New(nil).ScanWithOverrides(ctx, tr, rules, nil)
		if err != nil {
			t.Fatalf("scan (off): %v", err)
		}

		// ON: text consumer over a buffer (never stdout).
		var buf bytes.Buffer
		sink := newProgressSink(&buf, true)
		on, err := scan.New(nil, scan.WithProgress(sink)).ScanWithOverrides(ctx, tr, rules, nil)
		if err != nil {
			t.Fatalf("scan (on): %v", err)
		}

		// Per-transaction non-deterministic fields (UUID, timestamps) are
		// normalized so the comparison targets the result SHAPE that would
		// be serialized to stdout, not the random ids.
		normalize(off)
		normalize(on)
		if !reflect.DeepEqual(off.Transactions, on.Transactions) {
			t.Errorf("result differs with progress on vs off:\noff=%+v\non =%+v",
				off.Transactions, on.Transactions)
		}
		// And progress on must have actually produced stderr-bound output,
		// proving the invariance isn't trivially because the sink was inert.
		if buf.Len() == 0 {
			t.Error("progress-on run produced no rendered output; sink was not exercised")
		}
	})
}

// normalize zeroes the non-deterministic per-transaction fields (random
// UUIDs, wall-clock timestamps) so two runs over the same fake transport
// compare equal on the meaningful, serialized-to-stdout shape. The status,
// step outcomes, and detail — the parts a stdout serializer actually emits
// — are left intact and are what the comparison targets.
func normalize(r *api.ScanResult) {
	for i := range r.Transactions {
		r.Transactions[i].TransactionID = uuid.UUID{}
		r.Transactions[i].StartedAt = time.Time{}
		r.Transactions[i].FinishedAt = time.Time{}
	}
}
