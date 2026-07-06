package pammodulearg_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/pammodulearg"
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

// @spec handler-pam-module-arg
// @ac AC-01
func TestApplyEnsure_AppendsArgWhenMissing(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Program the "is the arg already present?" check to report absent
	// (exit 1) so Apply proceeds to append.
	checkCmd := `grep 'pam_unix\.so' '/etc/pam.d/system-auth' -F 2>/dev/null | grep -F 'remember=5'`
	tp.Results[checkCmd] = &api.CommandResult{ExitCode: 1}
	h := pammodulearg.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"action": "ensure",
		"module": "pam_unix.so",
		"arg":    "remember=5",
		"files":  []string{"/etc/pam.d/system-auth"},
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "sed -i.bak", "remember=5") {
		t.Errorf("expected a sed append of the arg; runs=%v", tp.Runs)
	}
}

// @spec handler-pam-module-arg
// @ac AC-02
func TestApplyEnsure_NoOpWhenPresent(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	// Default unmatched command → exit 0, so the presence check reports
	// the arg already present; Apply must not edit the file.
	h := pammodulearg.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"action": "ensure",
		"module": "pam_unix.so",
		"arg":    "remember=5",
		"files":  []string{"/etc/pam.d/system-auth"},
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if anyRunContains(tp.Runs, "sed -i.bak") {
		t.Errorf("expected no file edit on no-op; runs=%v", tp.Runs)
	}
}

// @spec handler-pam-module-arg
// @ac AC-03
func TestApplyRemove_StripsArg(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := pammodulearg.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"action": "remove",
		"module": "pam_unix.so",
		"arg":    "remember=5",
		"files":  []string{"/etc/pam.d/system-auth"},
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "sed", "/etc/pam.d/system-auth") {
		t.Errorf("expected a sed remove on the file; runs=%v", tp.Runs)
	}
}

// @spec handler-pam-module-arg
// @ac AC-04
// @spec handler-interface
// @ac AC-02
func TestCapture_RecordsAffectedLines(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-04", func(t *testing.T) {})
	t.Run("handler-interface/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	const prior = "auth required pam_unix.so\naccount required pam_unix.so\n"
	captureCmd := `if [ -e '/etc/pam.d/system-auth' ]; then base64 '/etc/pam.d/system-auth'; else printf '%s' '__KENSA_ABSENT__'; fi`
	tp.Results[captureCmd] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte(prior))}
	h := pammodulearg.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"action": "ensure",
		"module": "pam_unix.so",
		"arg":    "remember=5",
		"files":  []string{"/etc/pam.d/system-auth"},
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	content, ok := pre.Data["files_content"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing files_content; data=%v", pre.Data)
	}
	got, _ := content["/etc/pam.d/system-auth"].(string)
	if got != prior {
		t.Errorf("capture did not record the whole prior content; got %q want %q", got, prior)
	}
	existed, _ := pre.Data["files_existed"].(map[string]interface{})
	if e, _ := existed["/etc/pam.d/system-auth"].(bool); !e {
		t.Errorf("expected files_existed[file]=true; data=%v", pre.Data)
	}
}

// @spec handler-pam-module-arg
// @ac AC-05
// @spec handler-interface
// @ac AC-03
func TestRollback_RestoresCapturedLines(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-05", func(t *testing.T) {})
	t.Run("handler-interface/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := pammodulearg.New()
	pre := &api.PreState{
		Mechanism:  "pam_module_arg",
		Capturable: true,
		Data: map[string]interface{}{
			"module": "pam_unix.so",
			"files_snapshot": map[string]interface{}{
				"/etc/pam.d/system-auth": "5:auth required pam_unix.so\n",
			},
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "sed -i.bak", "5s/.*/") {
		t.Errorf("expected a sed line-restore; runs=%v", tp.Runs)
	}
}

// @spec handler-pam-module-arg
// @ac AC-06
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-06", func(t *testing.T) {})
	h := pammodulearg.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"missing action", api.Params{"module": "pam_unix.so", "arg": "x", "files": []string{"f"}}},
		{"invalid action", api.Params{"action": "bogus", "module": "pam_unix.so", "arg": "x", "files": []string{"f"}}},
		{"missing files", api.Params{"action": "ensure", "module": "pam_unix.so", "arg": "x"}},
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
	var _ api.CombinedHandler = pammodulearg.New()
}
