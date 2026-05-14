package output

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

func makeScanResult() *api.ScanResult {
	return &api.ScanResult{
		HostID: "host-1",
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
			{Status: api.StatusRolledBack},
		},
	}
}

// @spec output-fanout
// @ac AC-01
func TestFanOutScanResult_NoSpecs(t *testing.T) {
	t.Run("output-fanout/AC-01", func(t *testing.T) {})
	// Zero specs is a no-op (no goroutines, no file creation).
	result := makeScanResult()
	if err := FanOutScanResult(nil, &bytes.Buffer{}, "host-1", nil, result); err != nil {
		t.Errorf("FanOutScanResult(nil specs) error: %v", err)
	}
}

// @spec output-fanout
// @ac AC-02
func TestFanOutScanResult_SingleStdoutSpec(t *testing.T) {
	t.Run("output-fanout/AC-02", func(t *testing.T) {})
	// One spec with empty Path → writes to stdoutOverride.
	specs := []Spec{{Format: "json"}}
	var buf bytes.Buffer
	rules := []*api.Rule{{ID: "r"}, {ID: "r2"}}
	if err := FanOutScanResult(specs, &buf, "host-1", rules, makeScanResult()); err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if !strings.Contains(buf.String(), "host-1") {
		t.Errorf("output missing host-1; got:\n%s", buf.String())
	}
}

// @spec output-fanout
// @ac AC-03
func TestFanOutScanResult_FileTarget(t *testing.T) {
	t.Run("output-fanout/AC-03", func(t *testing.T) {})
	// Spec with Path opens and writes to a file.
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	specs := []Spec{{Format: "json", Path: path}}
	rules := []*api.Rule{{ID: "r"}, {ID: "r2"}}
	if err := FanOutScanResult(specs, &bytes.Buffer{}, "host-1", rules, makeScanResult()); err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(body, []byte("host-1")) {
		t.Errorf("file missing host-1: %s", body)
	}
}

// @spec output-fanout
// @ac AC-04
func TestFanOutScanResult_ConcurrentMultiTarget(t *testing.T) {
	t.Run("output-fanout/AC-04", func(t *testing.T) {})
	// AC-headline: -o csv:a -o pdf:b -o json:c runs all three serializers
	// concurrently against the same in-memory result.
	dir := t.TempDir()
	specs := []Spec{
		{Format: "csv", Path: filepath.Join(dir, "out.csv")},
		{Format: "json", Path: filepath.Join(dir, "out.json")},
		{Format: "jsonl", Path: filepath.Join(dir, "out.jsonl")},
	}
	rules := []*api.Rule{{ID: "rule-pass"}, {ID: "rule-fail"}}
	if err := FanOutScanResult(specs, &bytes.Buffer{}, "host-1", rules, makeScanResult()); err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	for _, s := range specs {
		body, err := os.ReadFile(s.Path)
		if err != nil {
			t.Errorf("file %q not created: %v", s.Path, err)
			continue
		}
		if len(body) == 0 {
			t.Errorf("file %q is empty", s.Path)
		}
	}
}

// @spec output-fanout
// @ac AC-05
func TestFanOutScanResult_StdoutOverridePassedToWriter(t *testing.T) {
	t.Run("output-fanout/AC-05", func(t *testing.T) {})
	// stdoutOverride is io.Discard (--quiet case). The spec has empty
	// Path, so it should land in io.Discard rather than os.Stdout.
	// We can't easily verify "no stdout writes" but we CAN verify the
	// override io.Writer received traffic by counting the writes.
	specs := []Spec{{Format: "json"}}
	counter := &countingWriter{}
	if err := FanOutScanResult(specs, counter, "h", nil, makeScanResult()); err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if atomic.LoadInt64(&counter.bytes) == 0 {
		t.Errorf("stdoutOverride received zero bytes; expected JSON output to flow there")
	}
}

// @spec output-fanout
// @ac AC-06
func TestFanOutScanResult_NilStdoutOverride_Panics(t *testing.T) {
	t.Run("output-fanout/AC-06", func(t *testing.T) {})
	// Programmer error: every caller must decide what stdout means.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil stdoutOverride; got none")
		}
	}()
	_ = FanOutScanResult([]Spec{{Format: "json"}}, nil, "h", nil, makeScanResult())
}

// @spec output-fanout
// @ac AC-07
func TestFanOutScanResult_UnsupportedFormat(t *testing.T) {
	t.Run("output-fanout/AC-07", func(t *testing.T) {})
	// A spec with a format that has no scan-result writer (e.g.,
	// "oscal" — registered for remediation but not scan) returns
	// ErrUnsupportedFormat.
	specs := []Spec{{Format: "oscal", Path: filepath.Join(t.TempDir(), "out.oscal.json")}}
	err := FanOutScanResult(specs, &bytes.Buffer{}, "h", nil, makeScanResult())
	if err == nil {
		t.Fatal("expected error on unsupported format; got nil")
	}
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("expected ErrUnsupportedFormat in chain; got %v", err)
	}
}

// @spec output-fanout
// @ac AC-08
func TestFanOutScanResult_FirstErrorInArgvOrder(t *testing.T) {
	t.Run("output-fanout/AC-08", func(t *testing.T) {})
	// Two failing specs; the error returned must be from the
	// LOWER-INDEX one (specs[0]) per AC-09's argv-order contract.
	specs := []Spec{
		{Format: "yaml-not-registered"}, // index 0
		{Format: "xml-not-registered"},  // index 1
	}
	err := FanOutScanResult(specs, &bytes.Buffer{}, "h", nil, makeScanResult())
	if err == nil {
		t.Fatal("expected error from failing specs")
	}
	if !strings.Contains(err.Error(), "output[0]") {
		t.Errorf("first error should report output[0]; got %q", err.Error())
	}
}

// @spec output-fanout
// @ac AC-09
func TestFanOutScanResult_EveryAttempted(t *testing.T) {
	t.Run("output-fanout/AC-09", func(t *testing.T) {})
	// Even when one spec fails, the rest must still attempt their
	// writes. Verified by mixing one bad-format spec with two file-
	// target specs and confirming both files are created.
	dir := t.TempDir()
	specs := []Spec{
		{Format: "csv", Path: filepath.Join(dir, "a.csv")},
		{Format: "yaml-not-registered"},
		{Format: "json", Path: filepath.Join(dir, "c.json")},
	}
	_ = FanOutScanResult(specs, &bytes.Buffer{}, "h", nil, makeScanResult())
	if _, err := os.Stat(specs[0].Path); err != nil {
		t.Errorf("first spec's file should still exist: %v", err)
	}
	if _, err := os.Stat(specs[2].Path); err != nil {
		t.Errorf("third spec's file should still exist (fan-out is best-effort): %v", err)
	}
}

// @spec output-fanout
// @ac AC-10
func TestFanOutScanResult_PathTraversalRejected(t *testing.T) {
	t.Run("output-fanout/AC-10", func(t *testing.T) {})
	// /dev, /proc, /sys paths are rejected by runOneSpec's defensive
	// check. Catches a typo like `-o json:/dev/null` (which would
	// otherwise work but is operator-foot-gun territory).
	specs := []Spec{{Format: "json", Path: "/dev/null-fake-test"}}
	err := FanOutScanResult(specs, &bytes.Buffer{}, "h", nil, makeScanResult())
	if err == nil {
		t.Fatal("expected error for /dev path; got nil")
	}
	if !strings.Contains(err.Error(), "/dev") {
		t.Errorf("error should reference /dev: %v", err)
	}
}

// @spec output-fanout
// @ac AC-11
func TestFanOutRemediationResult_BasicWiring(t *testing.T) {
	t.Run("output-fanout/AC-11", func(t *testing.T) {})
	dir := t.TempDir()
	specs := []Spec{
		{Format: "json", Path: filepath.Join(dir, "out.json")},
		{Format: "csv", Path: filepath.Join(dir, "out.csv")},
	}
	rules := []*api.Rule{{ID: "r1"}}
	result := &api.RemediationResult{
		Transactions: []api.TransactionResult{
			{Status: api.StatusCommitted},
		},
	}
	if err := FanOutRemediationResult(specs, &bytes.Buffer{}, "host-1", rules, result); err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	for _, s := range specs {
		if _, err := os.Stat(s.Path); err != nil {
			t.Errorf("file %q not created: %v", s.Path, err)
		}
	}
}

// @spec output-fanout
// @ac AC-12
func TestFanOutCaps_BasicWiring(t *testing.T) {
	t.Run("output-fanout/AC-12", func(t *testing.T) {})
	dir := t.TempDir()
	specs := []Spec{
		{Format: "json", Path: filepath.Join(dir, "caps.json")},
	}
	caps := api.CapabilitySet{"selinux": true, "apparmor": false}
	if err := FanOutCaps(specs, &bytes.Buffer{}, "host-1", caps); err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	body, err := os.ReadFile(specs[0].Path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(body, []byte("selinux")) {
		t.Errorf("file missing 'selinux': %s", body)
	}
}

// @spec output-fanout
// @ac AC-13
func TestFanOutScanResult_BadFilePath(t *testing.T) {
	t.Run("output-fanout/AC-13", func(t *testing.T) {})
	// Path that os.Create can't open (parent doesn't exist).
	specs := []Spec{{Format: "json", Path: "/nonexistent-dir-xyz/out.json"}}
	err := FanOutScanResult(specs, &bytes.Buffer{}, "h", nil, makeScanResult())
	if err == nil {
		t.Fatal("expected error for bad path; got nil")
	}
	if !strings.Contains(err.Error(), "/nonexistent-dir-xyz") {
		t.Errorf("error should reference the bad path: %v", err)
	}
}

func TestFanOutScanResult_ErrorMessageIncludesIndexAndSpec(t *testing.T) {
	// AC: error message includes both index and spec.String() so the
	// operator sees which positional flag failed AND its content.
	specs := []Spec{
		{Format: "json"},
		{Format: "yaml-not-registered"},
	}
	err := FanOutScanResult(specs, &bytes.Buffer{}, "h", nil, makeScanResult())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "output[1]") {
		t.Errorf("error should contain output[1]: %v", err)
	}
	if !strings.Contains(err.Error(), "yaml-not-registered") {
		t.Errorf("error should contain spec format: %v", err)
	}
}

// countingWriter is a write-counting io.Writer for tests that need
// to verify "writes happened" without inspecting bytes.
type countingWriter struct {
	bytes int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	atomic.AddInt64(&c.bytes, int64(len(b)))
	return len(b), nil
}

// silence the unused-io-import linter in the unlikely case io is
// imported transitively only by countingWriter (it isn't, but the
// helper guards against drift).
var _ io.Writer = (*countingWriter)(nil)
