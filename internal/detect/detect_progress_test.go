package detect

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/progress"
)

// recordingSink records every Update delivered to it.
type recordingSink struct {
	got []progress.Update
}

func (r *recordingSink) Update(u progress.Update) { r.got = append(r.got, u) }

// panicSink panics on every Update, exercising the guarantee that a
// misbehaving sink cannot break a detect run.
type panicSink struct{}

func (panicSink) Update(progress.Update) { panic("detect sink boom") }

// TestDetectWithProgress_MatchesDetectAndEmits verifies that
// DetectWithProgress returns the same CapabilitySet as Detect, emits exactly
// one ProbeDone Update per probe (probe name in Detail, OK the result), and
// that a nil sink yields the same set as Detect. It also confirms Detect's
// signature is unchanged by calling it with the legacy two-arg form.
//
// @spec progress-emission
// @ac AC-03
func TestDetectWithProgress_MatchesDetectAndEmits(t *testing.T) {
	t.Run("progress-emission/AC-03", func(t *testing.T) {
		// One probe false (exit 1), the rest true (exit 0).
		results := allZeroResults()
		falseTarget := probes[0]
		results[falseTarget.cmd] = 1
		ft := &fakeTransport{results: results}

		// Detect (signature unchanged: two args).
		base, err := Detect(context.Background(), ft)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}

		// DetectWithProgress with a recording sink.
		sink := &recordingSink{}
		got, err := DetectWithProgress(context.Background(), ft, sink)
		if err != nil {
			t.Fatalf("DetectWithProgress: %v", err)
		}

		// Same capability set as Detect.
		if len(got) != len(base) {
			t.Fatalf("set size differs: DetectWithProgress=%d Detect=%d", len(got), len(base))
		}
		for _, p := range probes {
			if got[p.name] != base[p.name] {
				t.Errorf("capability %q differs: DetectWithProgress=%v Detect=%v",
					p.name, got[p.name], base[p.name])
			}
		}

		// Exactly one ProbeDone Update per probe, in order, with the
		// probe name in Detail, a 1-based Index, the total, and OK the
		// probe result.
		if len(sink.got) != len(probes) {
			t.Fatalf("expected %d ProbeDone updates, got %d", len(probes), len(sink.got))
		}
		for i, p := range probes {
			u := sink.got[i]
			if u.Kind != progress.ProbeDone {
				t.Errorf("update[%d] Kind = %d, want ProbeDone", i, u.Kind)
			}
			if u.Detail != p.name {
				t.Errorf("update[%d] Detail = %q, want probe name %q", i, u.Detail, p.name)
			}
			if u.Index != i+1 {
				t.Errorf("update[%d] Index = %d, want %d", i, u.Index, i+1)
			}
			if u.Total != len(probes) {
				t.Errorf("update[%d] Total = %d, want %d", i, u.Total, len(probes))
			}
			wantOK := p.name != falseTarget.name
			if u.OK != wantOK {
				t.Errorf("update[%d] (%s) OK = %v, want %v", i, p.name, u.OK, wantOK)
			}
		}

		// Nil sink equals Detect.
		nilGot, err := DetectWithProgress(context.Background(), ft, nil)
		if err != nil {
			t.Fatalf("DetectWithProgress(nil): %v", err)
		}
		for _, p := range probes {
			if nilGot[p.name] != base[p.name] {
				t.Errorf("nil-sink capability %q differs from Detect", p.name)
			}
		}
	})
}

// TestDetectWithProgress_PanicSinkDoesNotBreak verifies a sink that panics on
// every Update does not break detection — the full CapabilitySet is still
// returned.
//
// @spec progress-emission
// @ac AC-05
func TestDetectWithProgress_PanicSinkDoesNotBreak(t *testing.T) {
	t.Run("progress-emission/AC-05", func(t *testing.T) {
		ft := &fakeTransport{results: allZeroResults()}
		caps, err := DetectWithProgress(context.Background(), ft, panicSink{})
		if err != nil {
			t.Fatalf("DetectWithProgress returned err despite panicking sink: %v", err)
		}
		if len(caps) != len(probes) {
			t.Fatalf("expected %d capabilities despite panicking sink, got %d",
				len(probes), len(caps))
		}
	})
}
