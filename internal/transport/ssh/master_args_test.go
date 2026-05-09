// Internal tests for masterArgs (lower-case, package-private).
// Verifies the StrictHostKeyChecking branch added in C-027.
package ssh

import (
	"strings"
	"testing"
)

// hasOption returns true if args contains the consecutive pair
// "-o", value (e.g., "-o", "StrictHostKeyChecking=yes").
func hasOption(args []string, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-o" && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestMasterArgs_StrictHostKeysOff(t *testing.T) {
	cfg := Config{Host: "h", Port: 22}
	args := masterArgs(cfg, "/tmp/sock")
	if !hasOption(args, "StrictHostKeyChecking=accept-new") {
		t.Errorf("expected StrictHostKeyChecking=accept-new with default Config; args: %s",
			strings.Join(args, " "))
	}
	if hasOption(args, "StrictHostKeyChecking=yes") {
		t.Errorf("did not expect StrictHostKeyChecking=yes with StrictHostKeys=false; args: %s",
			strings.Join(args, " "))
	}
}

func TestMasterArgs_StrictHostKeysOn(t *testing.T) {
	cfg := Config{Host: "h", Port: 22, StrictHostKeys: true}
	args := masterArgs(cfg, "/tmp/sock")
	if !hasOption(args, "StrictHostKeyChecking=yes") {
		t.Errorf("expected StrictHostKeyChecking=yes with StrictHostKeys=true; args: %s",
			strings.Join(args, " "))
	}
	if hasOption(args, "StrictHostKeyChecking=accept-new") {
		t.Errorf("did not expect StrictHostKeyChecking=accept-new with StrictHostKeys=true; args: %s",
			strings.Join(args, " "))
	}
	// Defense-in-depth: under strict mode we must also set
	// UpdateHostKeys=no, or OpenSSH 8.5+ silently learns rotated
	// keys from the server, partially defeating the strict
	// guarantee.
	if !hasOption(args, "UpdateHostKeys=no") {
		t.Errorf("expected UpdateHostKeys=no with StrictHostKeys=true; args: %s",
			strings.Join(args, " "))
	}
}

func TestMasterArgs_UpdateHostKeysAbsentWhenNotStrict(t *testing.T) {
	cfg := Config{Host: "h", Port: 22, StrictHostKeys: false}
	args := masterArgs(cfg, "/tmp/sock")
	if hasOption(args, "UpdateHostKeys=no") {
		t.Errorf("UpdateHostKeys=no should only be set under strict mode; args: %s",
			strings.Join(args, " "))
	}
}
