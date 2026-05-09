// Tests for the --strict-host-keys / --no-strict-host-keys flag
// pair (C-027). Covers the resolver: neither, strict-only,
// no-strict-only, and the both-flags-set conflict.
package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func newStrictTestFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	registerStrictHostKeysFlag(fs)
	return fs
}

func TestResolveStrictHostKeys_NeitherFlag(t *testing.T) {
	fs := newStrictTestFlagSet()
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := resolveStrictHostKeys(fs)
	if err != nil {
		t.Fatalf("neither: %v", err)
	}
	if got {
		t.Errorf("neither flag should resolve to false (TOFU default); got true")
	}
	// Fence the default at the registration layer too: a future
	// refactor that flips the default to true would let this
	// "neither" test still pass via the Changed-based logic. Catch
	// that drift here.
	if def := fs.Lookup("strict-host-keys").DefValue; def != "false" {
		t.Errorf("--strict-host-keys default must remain false to match Python kensa; got %q", def)
	}
	if def := fs.Lookup("no-strict-host-keys").DefValue; def != "false" {
		t.Errorf("--no-strict-host-keys default must remain false; got %q", def)
	}
}

func TestResolveStrictHostKeys_StrictOnly(t *testing.T) {
	fs := newStrictTestFlagSet()
	if err := fs.Parse([]string{"--strict-host-keys"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := resolveStrictHostKeys(fs)
	if err != nil {
		t.Fatalf("strict-only: %v", err)
	}
	if !got {
		t.Errorf("--strict-host-keys should resolve to true; got false")
	}
}

func TestResolveStrictHostKeys_NoStrictOnly(t *testing.T) {
	fs := newStrictTestFlagSet()
	if err := fs.Parse([]string{"--no-strict-host-keys"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := resolveStrictHostKeys(fs)
	if err != nil {
		t.Fatalf("no-strict-only: %v", err)
	}
	if got {
		t.Errorf("--no-strict-host-keys should resolve to false; got true")
	}
}

// TestStrictHostKeys_AllSSHSubcommandsAdvertiseFlags locks AC-08:
// every subcommand that opens an SSH transport must advertise
// both --strict-host-keys and --no-strict-host-keys in --help.
// Spawns ./bin/kensa as a subprocess; skipped when bin is not
// built (so plain `go test ./...` doesn't fail for someone who
// hasn't run `make build` yet).
func TestStrictHostKeys_AllSSHSubcommandsAdvertiseFlags(t *testing.T) {
	bin := findKensaBin(t)
	if bin == "" {
		t.Skip("bin/kensa not built; run `make build` to enable")
	}
	subcommands := []string{"detect", "check", "remediate", "rollback", "plan"}
	for _, sub := range subcommands {
		t.Run(sub, func(t *testing.T) {
			out, err := exec.Command(bin, sub, "--help").CombinedOutput()
			if err != nil {
				t.Fatalf("%s --help: %v\n%s", sub, err, out)
			}
			text := string(out)
			if !strings.Contains(text, "--strict-host-keys") {
				t.Errorf("%s --help missing --strict-host-keys", sub)
			}
			if !strings.Contains(text, "--no-strict-host-keys") {
				t.Errorf("%s --help missing --no-strict-host-keys", sub)
			}
		})
	}
}

// findKensaBin returns the path to ./bin/kensa relative to the
// test working directory. Walks up to the module root if needed.
func findKensaBin(t *testing.T) string {
	t.Helper()
	candidates := []string{"./bin/kensa", "../../bin/kensa", "../bin/kensa"}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func TestResolveStrictHostKeys_BothFlagsConflict(t *testing.T) {
	fs := newStrictTestFlagSet()
	if err := fs.Parse([]string{"--strict-host-keys", "--no-strict-host-keys"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	_, err := resolveStrictHostKeys(fs)
	if err == nil {
		t.Fatal("both flags set should error, got nil")
	}
	if !strings.Contains(err.Error(), "strict-host-keys") {
		t.Errorf("error should reference strict-host-keys: %v", err)
	}
	if !strings.Contains(err.Error(), "no-strict-host-keys") {
		t.Errorf("error should reference no-strict-host-keys: %v", err)
	}
	var ue *UsageError
	if !errors.As(err, &ue) {
		t.Errorf("conflict should produce a UsageError (exit 2 path); got %T", err)
	}
}
