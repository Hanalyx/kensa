package servicedbus_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serviceHandlerPackages are the three handlers whose shell capture must go
// through the shared unit-state command and parser.
var serviceHandlerPackages = []string{"servicedisabled", "serviceenabled", "servicemasked"}

// TestNoHandlerParsesUnitStatePositionally is a source-level drift guard.
//
// The defect this package's ParseUnitState exists to fix was not one bug: it
// was one bug copy-pasted into three handlers, which is why it read
// identically wrong in all of them and why fixing a single handler would
// have shipped the other two broken. A future handler that grows its own
// unit-state reader would reintroduce exactly that, and no behavioral test
// in this package would notice — the new copy would be somewhere else.
//
// So this asserts the structural property directly: no service handler
// carries `--value` on a unit-state read, and none indexes `systemctl show`
// output by line.
//
// @spec service-unit-state-parse
// @ac AC-05
func TestNoHandlerParsesUnitStatePositionally(t *testing.T) {
	t.Run("service-unit-state-parse/AC-05", func(t *testing.T) {})

	for _, pkg := range serviceHandlerPackages {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			text := string(src)

			// --value makes systemd print bare values in its own order.
			// Neither production code nor a fixture may reintroduce it:
			// a fixture carrying it is asserting the broken command shape.
			if strings.Contains(text, "UnitFileState -p ActiveState --value") {
				t.Errorf("%s reads unit state with --value; use servicedbus.ShowUnitStateCmd "+
					"(--value prints values in systemd's own property order, which is what "+
					"swapped prior_enabled and prior_active)", path)
			}
			// A local parser named like the one that was removed.
			if strings.Contains(text, "func parseShowOutput") {
				t.Errorf("%s defines its own unit-state parser; use servicedbus.ParseUnitState "+
					"(three copies of this parser is how one misreading became three defects)", path)
			}
		}
	}
}

// TestUnitStateFixturesUseRealSystemdForm holds the fixture-fidelity line.
//
// The inverted capture survived 23 tagged releases because the fixtures
// asserting it returned "enabled\nactive\n" — the order the code asked
// for, which systemd never emits. Offline gates cannot catch a defect their
// own fixtures encode, so the fixture shape itself has to be the assertion.
//
// @spec service-unit-state-parse
// @ac AC-06
func TestUnitStateFixturesUseRealSystemdForm(t *testing.T) {
	t.Run("service-unit-state-parse/AC-06", func(t *testing.T) {})

	for _, pkg := range serviceHandlerPackages {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			text := string(src)
			if !strings.Contains(text, "systemctl show -p UnitFileState -p ActiveState") {
				continue
			}
			if !strings.Contains(text, "UnitFileState=") {
				t.Errorf("%s programs a unit-state read but its fixture is not in systemd's "+
					"key=value form; reproduce real output (ActiveState= first, UnitFileState= second)", path)
			}
		}
	}
}
