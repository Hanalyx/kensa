package scan_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/scan"
)

// TestRemediate_AlreadyCompliantIsPublishedNotInferred: a rule that was already
// passing produces StatusCommitted, and so does a real remediation that
// succeeded. A consumer reading Status alone cannot tell them apart, so it may
// mark the request executed, report the rule fixed, and offer a rollback
// control for a transaction that mutated nothing and captured no state to
// restore.
//
// An overstated badge is a reporting bug; offering to reverse a change that
// never happened is a different class, which is why the fact is published
// rather than left derivable.
//
// This drives the real scanner rather than constructing the result, because the
// value of the field is that the PRODUCER sets it. Asserting it on a struct
// literal would pass with the producer removed — which is how the first version
// of this test failed its own mutation check.
//
// It also asserts the fact is published rather than derivable. Kensa's own text
// output used to infer it by matching Mechanism=="check" against the substring
// "already in desired state" in a free-text Detail field, which any rewording
// of that human-readable string would break.
//
// @spec scan-compliance-outcome
// @ac AC-09
func TestRemediate_AlreadyCompliantIsPublishedNotInferred(t *testing.T) {
	t.Log("// @spec scan-compliance-outcome")
	t.Log("// @ac AC-09")

	// Check passes -> nothing is applied.
	passing := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "0", ExitCode: 0},
	}}
	skipped, err := scan.New(&fakeEngine{}).Remediate(
		context.Background(), passing, []*api.Rule{minimalRule("skip-rule")})
	if err != nil {
		t.Fatalf("Remediate (passing): %v", err)
	}
	if len(skipped.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(skipped.Transactions))
	}

	// Check fails -> the engine runs and really remediates.
	failing := &fakeTransport{results: map[string]api.CommandResult{
		"sysctl -n 'net.ipv4.ip_forward'": {Stdout: "1", ExitCode: 0},
	}}
	remediated, err := scan.New(&fakeEngine{}).Remediate(
		context.Background(), failing, []*api.Rule{minimalRule("fix-rule")})
	if err != nil {
		t.Fatalf("Remediate (failing): %v", err)
	}
	if len(remediated.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(remediated.Transactions))
	}

	skip, fix := skipped.Transactions[0], remediated.Transactions[0]

	// The defect: Status alone cannot separate them.
	if skip.Status != fix.Status {
		t.Fatalf("precondition changed: skipped=%s remediated=%s no longer share a "+
			"Status, so this test no longer tests what it claims", skip.Status, fix.Status)
	}

	if !skip.AlreadyCompliant {
		t.Error("a rule that was already in the desired state did not report " +
			"AlreadyCompliant; a consumer would offer to roll back a change that never happened")
	}
	if fix.AlreadyCompliant {
		t.Error("a rule the engine actually remediated reported AlreadyCompliant")
	}

	// The record must also agree with itself. Publishing AlreadyCompliant
	// while leaving these two contradicting their own "if and only if"
	// contracts would replace one ambiguity with two, and the spec claims
	// this test locks them — so it has to.
	if !skip.HostUnchanged {
		t.Error("an already-compliant skip reported HostUnchanged=false, publishing " +
			"a mutation that never happened on a field consumers persist")
	}
	if skip.CommittedAt == nil {
		t.Error("StatusCommitted with a nil CommittedAt contradicts that field's " +
			"documented if-and-only-if")
	}
	// The negative direction: a real remediation must not borrow the no-op's
	// claim of an untouched host.
	if fix.HostUnchanged {
		t.Error("a real remediation reported HostUnchanged=true")
	}
}
