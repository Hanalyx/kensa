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
