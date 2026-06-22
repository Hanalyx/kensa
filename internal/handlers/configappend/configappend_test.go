package configappend_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/configappend"
)

// anyRunContains reports whether any recorded command contains all subs.
func anyRunContains(runs []string, subs ...string) bool {
	for _, r := range runs {
		all := true
		for _, s := range subs {
			if !strings.Contains(r, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

const (
	testPath = "/etc/sysctl.conf"
	testLine = "net.ipv4.ip_forward=0"
)

// @spec handler-config-append
// @ac AC-01
func TestApply_AppendsLineWhenAbsent(t *testing.T) {
	t.Run("handler-config-append/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Program the exact-line presence check to report absent (exit 1) so
	// Apply proceeds to append.
	checkCmd := "grep -qxF '" + testLine + "' '" + testPath + "'"
	tp.Results[checkCmd] = &api.CommandResult{ExitCode: 1}
	h := configappend.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"path": testPath,
		"line": testLine,
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "echo '"+testLine+"' >> '"+testPath+"'") {
		t.Errorf("expected an echo append of the line; runs=%v", tp.Runs)
	}
}

// @spec handler-config-append
// @ac AC-02
func TestApply_NoOpWhenPresent(t *testing.T) {
	t.Run("handler-config-append/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Default unmatched command → exit 0, so the presence check reports
	// the line already present; Apply must not append.
	h := configappend.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"path": testPath,
		"line": testLine,
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if anyRunContains(tp.Runs, "echo") {
		t.Errorf("expected no append on no-op; runs=%v", tp.Runs)
	}
}

// @spec handler-config-append
// @ac AC-03
// @spec handler-interface
// @ac AC-02
func TestCapture_RecordsWasPresent(t *testing.T) {
	t.Run("handler-config-append/AC-03", func(t *testing.T) {})
	t.Run("handler-interface/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Capture reads the file content (test -e && cat); program it to return
	// content already containing the exact line → was_present=true.
	catCmd := "test -e '" + testPath + "' && cat '" + testPath + "' || printf '__KENSA_ABSENT__'"
	tp.Results[catCmd] = &api.CommandResult{Stdout: "# header\n" + testLine + "\n"}
	h := configappend.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"path": testPath,
		"line": testLine,
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	wasPresent, ok := pre.Data["was_present"].(bool)
	if !ok {
		t.Fatalf("missing was_present; data=%v", pre.Data)
	}
	if !wasPresent {
		t.Errorf("expected was_present=true when the line is in the content; data=%v", pre.Data)
	}
	if got, _ := pre.Data["prior_content"].(string); got != "# header\n"+testLine+"\n" {
		t.Errorf("prior_content not recorded for byte-perfect restore; got %q", got)
	}
	if got, _ := pre.Data["path"].(string); got != testPath {
		t.Errorf("path recorded = %q, want %q", got, testPath)
	}
}

// @spec handler-config-append
// @ac AC-04
// @spec handler-interface
// @ac AC-03
func TestRollback_RemovesAddedLineButKeepsPreExisting(t *testing.T) {
	t.Run("handler-config-append/AC-04", func(t *testing.T) {})
	t.Run("handler-config-append/AC-06", func(t *testing.T) {})
	t.Run("handler-interface/AC-03", func(t *testing.T) {})
	h := configappend.New()

	// was_present=false → Apply added the line → rollback removes it.
	tpAdded := engine.NewFakeTransport()
	preAdded := &api.PreState{
		Mechanism:  "config_append",
		Capturable: true,
		Data: map[string]interface{}{
			"path":        testPath,
			"line":        testLine,
			"was_present": false,
		},
	}
	res, err := h.Rollback(context.Background(), tpAdded, preAdded)
	if err != nil {
		t.Fatalf("Rollback (added): %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// sed pattern escapes the dots in the line; verify the sed delete ran.
	if !anyRunContains(tpAdded.Runs, `sed -i '/^net\.ipv4\.ip_forward=0$/d' '`+testPath+`'`) {
		t.Errorf("expected a sed line-delete; runs=%v", tpAdded.Runs)
	}

	// was_present=true → line pre-existed → rollback leaves file untouched.
	tpPre := engine.NewFakeTransport()
	prePre := &api.PreState{
		Mechanism:  "config_append",
		Capturable: true,
		Data: map[string]interface{}{
			"path":        testPath,
			"line":        testLine,
			"was_present": true,
		},
	}
	res2, err := h.Rollback(context.Background(), tpPre, prePre)
	if err != nil {
		t.Fatalf("Rollback (pre-existing): %v", err)
	}
	if !res2.Success {
		t.Errorf("Success=false: %s", res2.Detail)
	}
	if anyRunContains(tpPre.Runs, "sed") {
		t.Errorf("expected no edit for pre-existing line; runs=%v", tpPre.Runs)
	}
}

// @spec handler-config-append
// @ac AC-05
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-config-append/AC-05", func(t *testing.T) {})
	h := configappend.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"nil params", nil},
		{"missing path", api.Params{"line": testLine}},
		{"empty path", api.Params{"path": "", "line": testLine}},
		{"non-string path", api.Params{"path": 42, "line": testLine}},
		{"missing line", api.Params{"path": testPath}},
		{"non-string line", api.Params{"path": testPath, "line": 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Apply(context.Background(), engine.NewFakeTransport(), tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
		})
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = configappend.New()
}
