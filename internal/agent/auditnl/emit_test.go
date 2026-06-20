package auditnl

import (
	"strings"
	"testing"
)

// formatPhaseMessage renders auditd-style key=value text with the result
// mapped from the ok flag.
//
// @spec engine-audit-emission
// @ac AC-04
func TestFormatPhaseMessage(t *testing.T) {
	t.Run("engine-audit-emission/AC-04", func(t *testing.T) {})
	ok := formatPhaseMessage("abc-123", "apply", true)
	if !strings.Contains(ok, "phase=apply") || !strings.Contains(ok, "txn=abc-123") || !strings.Contains(ok, "result=ok") {
		t.Errorf("ok message = %q", ok)
	}
	fail := formatPhaseMessage("abc-123", "rolled_back", false)
	if !strings.Contains(fail, "result=fail") {
		t.Errorf("fail message = %q", fail)
	}
	if !strings.HasPrefix(ok, "op=kensa_transaction") {
		t.Errorf("message should start with the op tag; got %q", ok)
	}
}

// NewEmitter never errors, and EmitPhase/Close are safe to call on the
// no-op emitter that results when the socket cannot be opened (the
// non-root CI case) — emission must never panic or block a transaction.
//
// @spec engine-audit-emission
// @ac AC-03
func TestNewEmitter_NoopSafe(t *testing.T) {
	t.Run("engine-audit-emission/AC-03", func(t *testing.T) {})
	em := NewEmitter() // non-root in CI → no-op emitter
	// Must not panic regardless of whether the socket opened.
	em.EmitPhase("txn-1", "apply", true)
	if err := em.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// A zero-value emitter is also safe.
	var zero *Emitter
	zero.EmitPhase("txn-2", "capture", true)
	if err := zero.Close(); err != nil {
		t.Errorf("zero Close: %v", err)
	}
}
