// Integration tests for the kensa-fuzz harness.
//
// These tests require a real RHEL host with SSH access. They are skipped
// when KENSA_FUZZ_HOST is unset so CI never blocks on host availability.
//
// To run locally against a test host:
//
//	KENSA_FUZZ_HOST=192.0.2.1 go test -v ./cmd/kensa-fuzz/ -run TestFuzz
//
// Optional overrides:
//
//	KENSA_FUZZ_USER=rhel        SSH user (default: ssh client default)
//	KENSA_FUZZ_KEY=/path/to/key SSH identity file
//	KENSA_FUZZ_SUDO=1           Wrap commands in sudo -n sh -c
package main

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Hanalyx/kensa-go/api"
)

// hostConfig builds a test config from KENSA_FUZZ_* env vars.
// Returns ("", false) when KENSA_FUZZ_HOST is unset so callers can skip.
func hostConfig(t *testing.T, mechanism, phase string, params api.Params) (config, bool) {
	t.Helper()
	host := os.Getenv("KENSA_FUZZ_HOST")
	if host == "" {
		return config{}, false
	}
	sudo := false
	if s := os.Getenv("KENSA_FUZZ_SUDO"); s != "" {
		sudo, _ = strconv.ParseBool(s)
	}
	return config{
		host:      host,
		port:      22,
		user:      os.Getenv("KENSA_FUZZ_USER"),
		keyPath:   os.Getenv("KENSA_FUZZ_KEY"),
		sudo:      sudo,
		mechanism: mechanism,
		phase:     phase,
		params:    params,
		timeout:   90 * time.Second,
	}, true
}

// assertRollback verifies the core invariant: after an injected failure,
// rollback must have run and fingerprints must match.
func assertRollback(t *testing.T, result *FuzzResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("runFuzz: %v", err)
	}
	if !result.RollbackRan {
		t.Errorf("rollback did not run (status=%q)", result.TransactionStatus)
	}
	if !result.FingerprintMatch {
		t.Errorf("fingerprint mismatch after rollback\n  pre:  %v\n  post: %v",
			result.PreFingerprint, result.PostFingerprint)
	}
}

// TestFuzzSysctlSet_Apply verifies that an injected apply failure causes
// rollback to restore the kernel parameter to its pre-capture value.
func TestFuzzSysctlSet_Apply(t *testing.T) {
	cfg, ok := hostConfig(t, "sysctl_set", "apply", api.Params{
		"key":   "kernel.dmesg_restrict",
		"value": "1",
	})
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}

	ctx := context.Background()
	result, err := runFuzz(ctx, cfg)
	assertRollback(t, result, err)
	if result.TransactionStatus != string(api.StatusRolledBack) {
		t.Errorf("expected status rolled_back, got %q", result.TransactionStatus)
	}
}

// TestFuzzSysctlSet_Validate verifies that an injected validate failure
// causes apply to be rolled back and host state to be restored.
func TestFuzzSysctlSet_Validate(t *testing.T) {
	cfg, ok := hostConfig(t, "sysctl_set", "validate", api.Params{
		"key":   "kernel.dmesg_restrict",
		"value": "1",
	})
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}

	ctx := context.Background()
	result, err := runFuzz(ctx, cfg)
	assertRollback(t, result, err)
	if result.TransactionStatus != string(api.StatusRolledBack) {
		t.Errorf("expected status rolled_back, got %q", result.TransactionStatus)
	}
}

// TestFuzzSysctlSet_Capture verifies that a capture-phase failure leaves
// the host unchanged (no apply ran) and the pre/post fingerprints match.
func TestFuzzSysctlSet_Capture(t *testing.T) {
	cfg, ok := hostConfig(t, "sysctl_set", "capture", api.Params{
		"key":   "kernel.dmesg_restrict",
		"value": "1",
	})
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}

	ctx := context.Background()
	result, err := runFuzz(ctx, cfg)
	if err != nil {
		t.Fatalf("runFuzz: %v", err)
	}
	// For capture-phase injection the engine errors before any apply runs.
	// No rollback occurs but the host is trivially unchanged.
	if result.TransactionStatus != string(api.StatusErrored) {
		t.Errorf("expected status errored, got %q", result.TransactionStatus)
	}
	if !result.FingerprintMatch {
		t.Errorf("fingerprint changed after capture-failure (host should be unmodified)\n  pre:  %v\n  post: %v",
			result.PreFingerprint, result.PostFingerprint)
	}
}

// TestFuzzFileContent_Apply verifies rollback correctness for the
// file_content handler, which writes a full file. This tests the
// file-restore path of rollback (write-then-chmod-then-chown).
func TestFuzzFileContent_Apply(t *testing.T) {
	cfg, ok := hostConfig(t, "file_content", "apply", api.Params{
		"path":    "/tmp/kensa-fuzz-test.txt",
		"content": "kensa fuzz test content\n",
		"owner":   "root",
		"group":   "root",
		"mode":    "0644",
	})
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}

	ctx := context.Background()
	result, err := runFuzz(ctx, cfg)
	assertRollback(t, result, err)
}

// TestFuzzFileContent_Validate verifies that validate-phase injection
// triggers rollback for the file_content handler.
func TestFuzzFileContent_Validate(t *testing.T) {
	cfg, ok := hostConfig(t, "file_content", "validate", api.Params{
		"path":    "/tmp/kensa-fuzz-test.txt",
		"content": "kensa fuzz validate test\n",
		"owner":   "root",
		"group":   "root",
		"mode":    "0644",
	})
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}

	ctx := context.Background()
	result, err := runFuzz(ctx, cfg)
	assertRollback(t, result, err)
}
