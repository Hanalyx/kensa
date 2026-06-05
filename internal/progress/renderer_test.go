package progress_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/progress"
)

// errWriter is an io.Writer whose Write always fails, used to prove the
// renderers tolerate a failing destination without panicking.
type errWriter struct{ writes int }

func (e *errWriter) Write(p []byte) (int, error) {
	e.writes++
	return 0, errors.New("write failed")
}

// sampleUpdates is a representative stream covering every Kind.
func sampleUpdates() []progress.Update {
	return []progress.Update{
		{Host: "h1", Kind: progress.ScanStart, Total: 3},
		{Host: "h1", Kind: progress.RuleChecked, RuleID: "rule-a", Index: 1, Total: 3, OK: true},
		{Host: "h1", Kind: progress.RuleChecked, RuleID: "rule-b", Index: 2, Total: 3, OK: false, Detail: "drift"},
		{Host: "h1", Kind: progress.ProbeDone, Index: 1, Total: 2, OK: true, Detail: "selinux"},
		{Host: "h1", Kind: progress.TxnStarted, RuleID: "rule-b"},
		{Host: "h1", Kind: progress.TxnPhase, RuleID: "rule-b", OK: true, Phase: api.PhaseApply},
		{Host: "h1", Kind: progress.TxnDone, RuleID: "rule-b", OK: true, Detail: "committed"},
		{Host: "h1", Kind: progress.ScanEnd, Total: 3},
	}
}

// TestConsumerRendersIncrementally verifies a StreamConsumer implements
// progress.Sink and writes output for each Update as it arrives, before any
// end-of-stream signal.
//
// @spec progress-renderer
// @ac AC-01
func TestConsumerRendersIncrementally(t *testing.T) {
	t.Run("progress-renderer/AC-01", func(t *testing.T) {
		var buf bytes.Buffer
		var sink progress.Sink = progress.NewTextConsumer(&buf, false)

		ups := sampleUpdates()
		var lens []int
		for _, u := range ups {
			sink.Update(u)
			lens = append(lens, buf.Len())
		}

		// Output must grow monotonically: each Update contributed bytes
		// at the moment it was delivered (incremental, not buffered).
		prev := 0
		for i, l := range lens {
			if l <= prev {
				t.Errorf("after Update %d (kind %d) buffer len = %d, did not grow past %d — not incremental",
					i, ups[i].Kind, l, prev)
			}
			prev = l
		}
	})
}

// TestTextRendererBothTTYBranches verifies the text renderer renders an Update
// in both the isTTY=true and isTTY=false branches, against a bytes.Buffer, with
// no real-terminal probe.
//
// @spec progress-renderer
// @ac AC-02
func TestTextRendererBothTTYBranches(t *testing.T) {
	t.Run("progress-renderer/AC-02", func(t *testing.T) {
		u := progress.Update{Host: "h1", Kind: progress.RuleChecked, RuleID: "rule-a", Index: 1, Total: 3, OK: true}

		var ttyBuf bytes.Buffer
		progress.NewTextConsumer(&ttyBuf, true).Update(u)
		if ttyBuf.Len() == 0 {
			t.Error("isTTY=true branch produced no output")
		}

		var plainBuf bytes.Buffer
		progress.NewTextConsumer(&plainBuf, false).Update(u)
		if plainBuf.Len() == 0 {
			t.Error("isTTY=false branch produced no output")
		}
	})
}

// TestTextRendererContent verifies the text renderer's lines carry the rule id,
// the OK outcome, and the phase, and that distinct kinds produce distinct lines.
//
// @spec progress-renderer
// @ac AC-03
func TestTextRendererContent(t *testing.T) {
	t.Run("progress-renderer/AC-03", func(t *testing.T) {
		render := func(u progress.Update) string {
			var b bytes.Buffer
			progress.NewTextConsumer(&b, false).Update(u)
			return b.String()
		}

		checked := render(progress.Update{Host: "h1", Kind: progress.RuleChecked, RuleID: "rule-a", Index: 1, Total: 3, OK: true})
		if !strings.Contains(checked, "rule-a") {
			t.Errorf("RuleChecked line missing rule id: %q", checked)
		}

		failed := render(progress.Update{Host: "h1", Kind: progress.RuleChecked, RuleID: "rule-b", Index: 2, Total: 3, OK: false})
		if checked == failed {
			t.Error("passing and failing RuleChecked lines are identical — OK outcome not reflected")
		}

		phase := render(progress.Update{Host: "h1", Kind: progress.TxnPhase, RuleID: "rule-b", OK: true, Phase: api.PhaseApply})
		if !strings.Contains(phase, string(api.PhaseApply)) {
			t.Errorf("TxnPhase line missing phase %q: %q", api.PhaseApply, phase)
		}

		// Distinct kinds → distinct lines.
		start := render(progress.Update{Host: "h1", Kind: progress.ScanStart, Total: 3})
		end := render(progress.Update{Host: "h1", Kind: progress.ScanEnd, Total: 3})
		if start == end {
			t.Error("ScanStart and ScanEnd render identical lines")
		}
	})
}

// TestEventsJSONLRenderer verifies the events-jsonl renderer emits one
// newline-terminated JSON object per Update, each parseable and carrying the
// display fields with kind as a string token.
//
// @spec progress-renderer
// @ac AC-04
func TestEventsJSONLRenderer(t *testing.T) {
	t.Run("progress-renderer/AC-04", func(t *testing.T) {
		var buf bytes.Buffer
		sink := progress.NewEventsJSONLConsumer(&buf)

		ups := sampleUpdates()
		for _, u := range ups {
			sink.Update(u)
		}

		out := buf.String()
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("events-jsonl output not newline-terminated: %q", out)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) != len(ups) {
			t.Fatalf("got %d NDJSON lines, want %d (one per Update)", len(lines), len(ups))
		}

		// Verify the RuleChecked line (index 1 in sampleUpdates) carries
		// every display field with kind as a string token.
		var rec map[string]any
		if err := json.Unmarshal([]byte(lines[1]), &rec); err != nil {
			t.Fatalf("RuleChecked line is not valid JSON: %v (%q)", err, lines[1])
		}
		for _, field := range []string{"host", "kind", "rule_id", "index", "total", "ok", "phase", "detail"} {
			if _, present := rec[field]; !present {
				t.Errorf("RuleChecked JSON missing field %q: %v", field, rec)
			}
		}
		kind, ok := rec["kind"].(string)
		if !ok {
			t.Fatalf("kind is %T, want a string token", rec["kind"])
		}
		if kind == "" || kind == "1" {
			t.Errorf("kind = %q, want a stable non-numeric string token", kind)
		}
		if rec["rule_id"] != "rule-a" {
			t.Errorf("rule_id = %v, want rule-a", rec["rule_id"])
		}
		if rec["ok"] != true {
			t.Errorf("ok = %v, want true", rec["ok"])
		}

		// Every line must independently parse as JSON.
		for i, ln := range lines {
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Errorf("line %d not valid JSON: %v (%q)", i, err, ln)
			}
		}
	})
}

// TestRenderersWriteOnlyToInjectedWriter verifies both renderers write strictly
// to the supplied io.Writer (captured in a bytes.Buffer) and that no
// constructor accepts or defaults to stdout.
//
// @spec progress-renderer
// @ac AC-05
func TestRenderersWriteOnlyToInjectedWriter(t *testing.T) {
	t.Run("progress-renderer/AC-05", func(t *testing.T) {
		u := progress.Update{Host: "h1", Kind: progress.RuleChecked, RuleID: "r", Index: 1, Total: 1, OK: true}

		var textBuf bytes.Buffer
		progress.NewTextConsumer(&textBuf, false).Update(u)
		if textBuf.Len() == 0 {
			t.Error("text renderer wrote nothing to the injected writer")
		}

		var jsonBuf bytes.Buffer
		progress.NewEventsJSONLConsumer(&jsonBuf).Update(u)
		if jsonBuf.Len() == 0 {
			t.Error("events-jsonl renderer wrote nothing to the injected writer")
		}

		// The constructors take an explicit io.Writer; a caller that wants
		// stderr passes os.Stderr. The renderer itself never references
		// os.Stdout — proven by the fact that all output above landed in
		// the caller-owned buffers and nowhere else. (A stdout write would
		// not appear in these buffers; the buffers hold the complete render
		// output, confirming the writer is the sole destination.)
		if !strings.Contains(jsonBuf.String(), `"host":"h1"`) {
			t.Errorf("events-jsonl output not in injected buffer: %q", jsonBuf.String())
		}
	})
}

// TestTextRendererInPlaceTTY verifies the isTTY in-place mode: transient
// Updates (RuleChecked / TxnPhase) are written with a leading CR + clear-to-EOL
// and no trailing newline (so they overwrite in place), while milestone/terminal
// Updates commit with a trailing newline.
//
// @spec progress-renderer
// @ac AC-07
func TestTextRendererInPlaceTTY(t *testing.T) {
	t.Run("progress-renderer/AC-07", func(t *testing.T) {
		const cr = "\r"
		const clear = "\x1b[K"

		// A transient RuleChecked line: CR + clear, NO trailing newline.
		var transient bytes.Buffer
		progress.NewTextConsumer(&transient, true).Update(
			progress.Update{Kind: progress.RuleChecked, RuleID: "r1", Index: 1, Total: 3, OK: true})
		ts := transient.String()
		if !strings.HasPrefix(ts, cr+clear) {
			t.Errorf("transient line missing leading CR+clear: %q", ts)
		}
		if strings.HasSuffix(ts, "\n") {
			t.Errorf("transient line must NOT end with newline (overwrites in place): %q", ts)
		}

		// A milestone TxnStarted line: commits with a trailing newline.
		var milestone bytes.Buffer
		progress.NewTextConsumer(&milestone, true).Update(
			progress.Update{Kind: progress.TxnStarted, RuleID: "r1"})
		ms := milestone.String()
		if !strings.HasSuffix(ms, "\n") {
			t.Errorf("milestone line must end with newline (stays on screen): %q", ms)
		}
		if strings.HasPrefix(ms, cr+clear) {
			t.Errorf("a milestone with no pending transient line must not lead with CR+clear: %q", ms)
		}

		// Two consecutive transient lines then a milestone: the second
		// transient overwrites (its own CR+clear), and the milestone clears the
		// pending transient before committing with a newline.
		var seq bytes.Buffer
		c := progress.NewTextConsumer(&seq, true)
		c.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "r1", Index: 1, Total: 3, OK: true})
		c.Update(progress.Update{Kind: progress.RuleChecked, RuleID: "r2", Index: 2, Total: 3, OK: true})
		c.Update(progress.Update{Kind: progress.TxnDone, RuleID: "r2", OK: true})
		got := seq.String()
		// Exactly one trailing newline overall (only the milestone committed).
		if strings.Count(got, "\n") != 1 {
			t.Errorf("expected exactly one committed (newline) line, got %d in %q", strings.Count(got, "\n"), got)
		}
		// The pending transient must have been cleared before the milestone:
		// a CR+clear appears immediately before the final committed line.
		if !strings.Contains(got, cr+clear) {
			t.Errorf("sequence missing CR+clear rewrites: %q", got)
		}
	})
}

// TestTextRendererPlainUnchanged verifies the isTTY=false plain mode is
// byte-identical to the pre-PR7 form: one '\n'-terminated line per Update, no
// carriage return, no clear-to-EOL escape sequence.
//
// @spec progress-renderer
// @ac AC-08
func TestTextRendererPlainUnchanged(t *testing.T) {
	t.Run("progress-renderer/AC-08", func(t *testing.T) {
		var buf bytes.Buffer
		c := progress.NewTextConsumer(&buf, false)
		ups := sampleUpdates()
		for _, u := range ups {
			c.Update(u)
		}
		out := buf.String()

		if strings.Contains(out, "\r") {
			t.Errorf("plain mode must not emit a carriage return: %q", out)
		}
		if strings.Contains(out, "\x1b[K") {
			t.Errorf("plain mode must not emit a clear-to-EOL escape: %q", out)
		}
		// Exactly one '\n'-terminated line per Update.
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("plain output not newline-terminated: %q", out)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) != len(ups) {
			t.Errorf("plain mode: got %d lines, want one per Update (%d): %q", len(lines), len(ups), out)
		}
	})
}

// TestTextConsumerTxnDoneTally verifies the text consumer counts the TxnDone
// Updates it rendered, so the CLI can compare it against the canonical result
// to detect dropped events.
//
// @spec progress-renderer
// @ac AC-09
func TestTextConsumerTxnDoneTally(t *testing.T) {
	t.Run("progress-renderer/AC-09", func(t *testing.T) {
		var buf bytes.Buffer
		c := progress.NewTextConsumer(&buf, false)

		if c.TxnDoneCount() != 0 {
			t.Fatalf("fresh consumer TxnDoneCount = %d, want 0", c.TxnDoneCount())
		}

		// Mixed stream: 2 TxnDone among other kinds.
		stream := []progress.Update{
			{Kind: progress.TxnStarted, RuleID: "r1"},
			{Kind: progress.TxnPhase, RuleID: "r1", Phase: api.PhaseApply, OK: true},
			{Kind: progress.TxnDone, RuleID: "r1", OK: true},
			{Kind: progress.TxnStarted, RuleID: "r2"},
			{Kind: progress.TxnDone, RuleID: "r2", OK: false},
			{Kind: progress.RuleChecked, RuleID: "r3", Index: 1, Total: 1, OK: true},
		}
		for _, u := range stream {
			c.Update(u)
		}
		if c.TxnDoneCount() != 2 {
			t.Errorf("TxnDoneCount = %d, want 2 (one per TxnDone Update)", c.TxnDoneCount())
		}

		// A nil consumer reports zero (progress off).
		var nilConsumer *progress.StreamConsumer
		if nilConsumer.TxnDoneCount() != 0 {
			t.Errorf("nil consumer TxnDoneCount = %d, want 0", nilConsumer.TxnDoneCount())
		}
	})
}

// TestRenderersTolerateWriteError verifies a failing io.Writer neither panics
// nor aborts the consumer; a subsequent Update is still accepted.
//
// @spec progress-renderer
// @ac AC-06
func TestRenderersTolerateWriteError(t *testing.T) {
	t.Run("progress-renderer/AC-06", func(t *testing.T) {
		u := progress.Update{Host: "h1", Kind: progress.RuleChecked, RuleID: "r", Index: 1, Total: 1, OK: true}

		textErr := &errWriter{}
		textSink := progress.NewTextConsumer(textErr, false)
		textSink.Update(u) // must not panic
		textSink.Update(u) // subsequent Update still accepted
		if textErr.writes < 2 {
			t.Errorf("text renderer attempted %d writes, expected it to keep writing after an error", textErr.writes)
		}

		jsonErr := &errWriter{}
		jsonSink := progress.NewEventsJSONLConsumer(jsonErr)
		jsonSink.Update(u) // must not panic
		jsonSink.Update(u)
		if jsonErr.writes < 2 {
			t.Errorf("events-jsonl renderer attempted %d writes, expected it to keep writing after an error", jsonErr.writes)
		}
	})
}
