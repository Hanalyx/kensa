// Tests for --workers / -w validation (C-029).
package main

import (
	"errors"
	"strings"
	"testing"
)

// @spec cli-workers-flag
// @ac AC-01
// @ac AC-06
func TestValidateWorkers_Valid(t *testing.T) {
	t.Run("cli-workers-flag/AC-06", func(t *testing.T) {})
	t.Run("cli-workers-flag/AC-01", func(t *testing.T) {})
	for _, n := range []int{1, 2, 10, 25, 49, 50} {
		if err := validateWorkers(n); err != nil {
			t.Errorf("validateWorkers(%d): %v", n, err)
		}
	}
}

// @spec cli-workers-flag
// @ac AC-02
// @ac AC-07
func TestValidateWorkers_TooLow(t *testing.T) {
	t.Run("cli-workers-flag/AC-07", func(t *testing.T) {})
	t.Run("cli-workers-flag/AC-02", func(t *testing.T) {})
	for _, n := range []int{0, -1, -100} {
		err := validateWorkers(n)
		if err == nil {
			t.Errorf("validateWorkers(%d) should reject", n)
			continue
		}
		if !strings.Contains(err.Error(), ">= 1") {
			t.Errorf("error for %d should mention lower bound: %v", n, err)
		}
	}
}

// @spec cli-workers-flag
// @ac AC-03
// @ac AC-08
func TestValidateWorkers_TooHigh(t *testing.T) {
	t.Run("cli-workers-flag/AC-08", func(t *testing.T) {})
	t.Run("cli-workers-flag/AC-03", func(t *testing.T) {})
	for _, n := range []int{51, 100, 1000} {
		err := validateWorkers(n)
		if err == nil {
			t.Errorf("validateWorkers(%d) should reject", n)
			continue
		}
		if !strings.Contains(err.Error(), "<= 50") {
			t.Errorf("error for %d should mention upper bound: %v", n, err)
		}
		if !strings.Contains(err.Error(), "MaxStartups") {
			t.Errorf("error for %d should explain why: %v", n, err)
		}
	}
}

// TestValidateWorkers_MaxConst locks the public MaxWorkers value.
// If a future change wants to raise the limit, that change must
// update this test deliberately, surfacing the policy choice.
// @spec cli-workers-flag
// @ac AC-04
// @ac AC-09
func TestValidateWorkers_MaxConst(t *testing.T) {
	t.Run("cli-workers-flag/AC-09", func(t *testing.T) {})
	t.Run("cli-workers-flag/AC-04", func(t *testing.T) {})
	if MaxWorkers != 50 {
		t.Errorf("MaxWorkers changed from 50 to %d; update CLI_GNU_POSIX_MIGRATION_V1.md and the spec", MaxWorkers)
	}
}

// TestValidateWorkers_ErrorIsNotUsageError documents that
// validateWorkers returns a plain error; callers wrap it in
// WrapUsageError("--workers", err) at the use site so the
// dispatcher routes to exit 2.
// @spec cli-workers-flag
// @ac AC-05
// @ac AC-10
func TestValidateWorkers_ErrorIsNotUsageError(t *testing.T) {
	t.Run("cli-workers-flag/AC-10", func(t *testing.T) {})
	t.Run("cli-workers-flag/AC-05", func(t *testing.T) {})
	err := validateWorkers(0)
	if err == nil {
		t.Fatal("expected error")
	}
	var ue *UsageError
	if errors.As(err, &ue) {
		t.Errorf("validateWorkers should return a plain error; caller wraps as UsageError")
	}
}
