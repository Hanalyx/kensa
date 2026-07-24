package check

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// dropinTransport returns a fixed (stdout, exit) for any grep command and
// records the command it saw. It models the real grep-over-base+dropin
// behavior — including exit code 2 when the *.conf.d glob is unmatched but the
// base file matched (a file-read error, not "no match"), the case that breaks a
// naive exit-code check.
type dropinTransport struct {
	stdout  string
	exit    int
	lastCmd string
}

func (d *dropinTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if strings.HasPrefix(cmd, "grep") {
		d.lastCmd = cmd
		return &api.CommandResult{ExitCode: d.exit, Stdout: d.stdout}, nil
	}
	return &api.CommandResult{ExitCode: 1}, nil
}
func (d *dropinTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (d *dropinTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (d *dropinTransport) ControlChannelSensitive() bool                           { return false }
func (d *dropinTransport) Close() error                                            { return nil }

// TestConfigValueDropinDir verifies the pwquality-class fix: config_value with
// dropin_dir reads the base file AND the *.conf.d/ drop-in directory, selects
// the LAST match (drop-in precedence), and does NOT treat grep's exit-2 (from an
// unmatched glob) as "not found" when the base file actually matched.
//
// @spec check-model
// @ac AC-01
func TestConfigValueDropinDir(t *testing.T) {
	t.Run("check-model/AC-01", func(t *testing.T) {})

	base := api.Params{
		"path": "/etc/security/pwquality.conf", "key": "difok",
		"expected": "8", "comparator": ">=",
		"dropin_dir": "/etc/security/pwquality.conf.d",
	}

	// (a) Value only in the drop-in, base absent → glob matched, exit 0.
	tr := &dropinTransport{stdout: "/etc/security/pwquality.conf.d/50-x.conf:difok = 8\n", exit: 0}
	if ok, d, _ := runForTest(context.Background(), tr, api.Check{Method: "config_value", Params: base}); !ok {
		t.Errorf("value in drop-in should PASS; detail=%q", d)
	}
	// The command must actually reference the drop-in glob.
	if !strings.Contains(tr.lastCmd, "pwquality.conf.d") || !strings.Contains(tr.lastCmd, "/*.conf") {
		t.Errorf("grep should include the drop-in glob; got %q", tr.lastCmd)
	}

	// (b) Drop-in OVERRIDES base with a non-compliant value (last-wins): base
	// difok=8 (compliant) but a later drop-in sets difok=2 → effective 2 < 8 → FAIL.
	tr = &dropinTransport{stdout: "/etc/security/pwquality.conf:difok = 8\n/etc/security/pwquality.conf.d/99-z.conf:difok = 2\n", exit: 0}
	if ok, d, _ := runForTest(context.Background(), tr, api.Check{Method: "config_value", Params: base}); ok {
		t.Errorf("last-wins: a drop-in difok=2 overriding base=8 must FAIL (>=8); detail=%q", d)
	}

	// (c) The exit-2 trap: drop-in dir absent so the glob is unmatched → grep
	// exits 2 EVEN THOUGH the base file matched difok=8. Must still PASS, not
	// be misread as "not found".
	tr = &dropinTransport{stdout: "/etc/security/pwquality.conf:difok = 8\n", exit: 2}
	if ok, d, _ := runForTest(context.Background(), tr, api.Check{Method: "config_value", Params: base}); !ok {
		t.Errorf("base match with exit-2 (unmatched glob) must PASS, not read as not-found; detail=%q", d)
	}

	// (d) Absent everywhere → empty stdout, exit 2 → FAIL.
	tr = &dropinTransport{stdout: "", exit: 2}
	if ok, d, _ := runForTest(context.Background(), tr, api.Check{Method: "config_value", Params: base}); ok {
		t.Errorf("absent key must FAIL; detail=%q", d)
	}
}
