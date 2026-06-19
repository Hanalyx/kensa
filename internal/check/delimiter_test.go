package check

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// lineTransport returns `line` (exit 0) for any grep command, else exit 1.
// It lets the delimiter test exercise checkConfigValue's value extraction
// without depending on the exact grep command string.
type lineTransport struct{ line string }

func (l *lineTransport) Run(_ context.Context, cmd string) (*api.CommandResult, error) {
	if strings.HasPrefix(cmd, "grep") {
		return &api.CommandResult{ExitCode: 0, Stdout: l.line}, nil
	}
	return &api.CommandResult{ExitCode: 1}, nil
}
func (l *lineTransport) Put(_ context.Context, _, _ string, _ fs.FileMode) error { return nil }
func (l *lineTransport) Get(_ context.Context, _, _ string) error                { return nil }
func (l *lineTransport) ControlChannelSensitive() bool                           { return false }
func (l *lineTransport) Close() error                                            { return nil }

// TestConfigValueWhitespaceDelimiter verifies the login.defs class fix: a
// config_value check with delimiter " " extracts the value from a
// whitespace-delimited "KEY value" line (the case that silently returned
// "not found" under the default "=" delimiter).
//
// @spec delimiter-model
// @ac AC-01
func TestConfigValueWhitespaceDelimiter(t *testing.T) {
	t.Run("delimiter-model/AC-01", func(t *testing.T) {})

	// "PASS_MAX_DAYS 60" with delimiter " " and comparator "<=" against 365.
	chk := api.Check{Method: "config_value", Params: api.Params{
		"path": "/etc/login.defs", "key": "PASS_MAX_DAYS",
		"expected": "365", "delimiter": " ", "comparator": "<=",
	}}
	tr := &lineTransport{line: "PASS_MAX_DAYS 60"}
	passed, detail, err := runForTest(context.Background(), tr, chk)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !passed {
		t.Errorf("whitespace-delimited key should be found and 60 <= 365 should PASS; detail=%q", detail)
	}

	// Multiple spaces ("KEY   value") must also extract cleanly.
	tr2 := &lineTransport{line: "PASS_WARN_AGE   7"}
	chk2 := api.Check{Method: "config_value", Params: api.Params{
		"path": "/etc/login.defs", "key": "PASS_WARN_AGE",
		"expected": "7", "delimiter": " ",
	}}
	passed2, detail2, _ := runForTest(context.Background(), tr2, chk2)
	if !passed2 {
		t.Errorf("multi-space line should extract '7' and equal 7; detail=%q", detail2)
	}

	// TAB-delimited ("KEY\tvalue") — the RHEL /etc/login.defs default the
	// space-only fix originally missed (false-FAIL on a compliant host, caught
	// by the live-test review). A whitespace delimiter " " MUST match TAB too.
	tr3 := &lineTransport{line: "PASS_WARN_AGE\t7"}
	chk3 := api.Check{Method: "config_value", Params: api.Params{
		"path": "/etc/login.defs", "key": "PASS_WARN_AGE",
		"expected": "7", "delimiter": " ",
	}}
	passed3, detail3, _ := runForTest(context.Background(), tr3, chk3)
	if !passed3 {
		t.Errorf("TAB-delimited key must be found and extracted (regression guard); detail=%q", detail3)
	}
}
