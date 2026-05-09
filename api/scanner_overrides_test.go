// Tests for scanWithOptionalOverrides / remediateWithOptionalOverrides
// (C-028 AC-10). Verifies that capability overrides + a Scanner
// that doesn't satisfy ScannerWithOverrides produces a clear error
// rather than silently falling back to detected-only caps.
package api

import (
	"context"
	"strings"
	"testing"
)

// legacyScanner satisfies only ScannerBackend, not
// ScannerWithOverrides. Used to verify the AC-10 mismatch path.
type legacyScanner struct {
	scanCalled      bool
	remediateCalled bool
}

func (l *legacyScanner) Scan(_ context.Context, _ Transport, _ []*Rule) (*ScanResult, error) {
	l.scanCalled = true
	return &ScanResult{}, nil
}

func (l *legacyScanner) Remediate(_ context.Context, _ Transport, _ []*Rule) (*RemediationResult, error) {
	l.remediateCalled = true
	return &RemediationResult{}, nil
}

func TestScanWithOptionalOverrides_NoOverrides_FallsBackToScan(t *testing.T) {
	scanner := &legacyScanner{}
	_, err := scanWithOptionalOverrides(context.Background(), scanner, nil, nil, nil)
	if err != nil {
		t.Fatalf("nil overrides: %v", err)
	}
	if !scanner.scanCalled {
		t.Error("expected legacy Scan to be called when overrides are nil")
	}
}

func TestScanWithOptionalOverrides_OverridesButLegacyScanner_Errors(t *testing.T) {
	scanner := &legacyScanner{}
	overrides := CapabilitySet{"selinux": true}
	_, err := scanWithOptionalOverrides(context.Background(), scanner, nil, nil, overrides)
	if err == nil {
		t.Fatal("expected error when overrides set + scanner does not implement ScannerWithOverrides")
	}
	if !strings.Contains(err.Error(), "capability overrides requested") {
		t.Errorf("error should mention overrides requested: %v", err)
	}
	if scanner.scanCalled {
		t.Error("legacy Scan should NOT be called when overrides requested")
	}
}

func TestRemediateWithOptionalOverrides_OverridesButLegacyScanner_Errors(t *testing.T) {
	scanner := &legacyScanner{}
	overrides := CapabilitySet{"selinux": true}
	_, err := remediateWithOptionalOverrides(context.Background(), scanner, nil, nil, overrides)
	if err == nil {
		t.Fatal("expected error when overrides set + scanner does not implement ScannerWithOverrides")
	}
	if !strings.Contains(err.Error(), "capability overrides requested") {
		t.Errorf("error should mention overrides requested: %v", err)
	}
	if scanner.remediateCalled {
		t.Error("legacy Remediate should NOT be called when overrides requested")
	}
}
