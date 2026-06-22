package pammodulearg_test

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/footprint"
	"github.com/Hanalyx/kensa/internal/agent/kernelio"
	"github.com/Hanalyx/kensa/internal/handlers/pammodulearg"
)

const (
	pamSystemAuth   = "/etc/pam.d/system-auth"
	pamPasswordAuth = "/etc/pam.d/password-auth"
)

// Kernel-IO ensure appends a missing arg to matching module lines through the
// funnel, leaving non-matching lines untouched.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-pam-module-arg
// @ac AC-07
func TestApplyEnsure_Kernel_AppendsViaFunnel(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-pam-module-arg/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[pamSystemAuth] = "auth required pam_env.so\npassword sufficient pam_unix.so sha512\n"
	h := pammodulearg.New()
	res, err := h.Apply(context.Background(), f, api.Params{
		"action": "ensure", "module": "pam_unix.so", "arg": "use_authtok", "type": "password",
		"files": []string{pamSystemAuth},
	}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	want := "auth required pam_env.so\npassword sufficient pam_unix.so sha512 use_authtok\n"
	if f.Files[pamSystemAuth] != want {
		t.Errorf("content=%q want %q", f.Files[pamSystemAuth], want)
	}
}

// Kernel-IO ensure is a no-op when a matching line already carries the arg.
//
// @spec handler-pam-module-arg
// @ac AC-07
func TestApplyEnsure_Kernel_NoOpWhenPresent(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	const orig = "password sufficient pam_unix.so sha512\n"
	f.Files[pamSystemAuth] = orig
	h := pammodulearg.New()
	res, err := h.Apply(context.Background(), f, api.Params{
		"action": "ensure", "module": "pam_unix.so", "arg": "sha512", "type": "password",
		"files": []string{pamSystemAuth},
	}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v", err, res.Success)
	}
	if f.Files[pamSystemAuth] != orig {
		t.Errorf("no-op edited the file: %q", f.Files[pamSystemAuth])
	}
}

// Kernel-IO remove strips a regex arg (the corpus remember=[0-9]* case) from
// matching lines while leaving the rest of the line intact.
//
// @spec handler-pam-module-arg
// @ac AC-07
func TestApplyRemove_Kernel_RegexArg(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	f.Files[pamSystemAuth] = "password sufficient pam_unix.so sha512 remember=5 shadow\n"
	h := pammodulearg.New()
	res, err := h.Apply(context.Background(), f, api.Params{
		"action": "remove", "module": "pam_unix.so", "arg": "remember=[0-9]*", "arg_regex": true,
		"files": []string{pamSystemAuth},
	}, nil)
	if err != nil || !res.Success {
		t.Fatalf("Apply: err=%v success=%v detail=%s", err, res.Success, res.Detail)
	}
	want := "password sufficient pam_unix.so sha512 shadow\n"
	if f.Files[pamSystemAuth] != want {
		t.Errorf("content=%q want %q", f.Files[pamSystemAuth], want)
	}
}

// Kernel-IO round trip: capture → ensure → rollback restores byte-perfect
// across multiple files.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-pam-module-arg
// @ac AC-07
func TestRoundTrip_Kernel_RestoresBytePerfect(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-pam-module-arg/AC-07", func(t *testing.T) {})
	f := kernelio.NewFakeSysctl()
	const a = "password sufficient pam_unix.so sha512\n"
	const b = "password sufficient pam_unix.so sha512\nauth required pam_faillock.so\n"
	f.Files[pamSystemAuth] = a
	f.Files[pamPasswordAuth] = b
	h := pammodulearg.New()
	params := api.Params{
		"action": "ensure", "module": "pam_unix.so", "arg": "use_authtok", "type": "password",
		"files": []string{pamSystemAuth, pamPasswordAuth},
	}
	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if _, err := h.Apply(context.Background(), f, params, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.Files[pamSystemAuth] == a {
		t.Fatal("apply should have edited system-auth")
	}
	if _, err := h.Rollback(context.Background(), f, pre); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if f.Files[pamSystemAuth] != a {
		t.Errorf("system-auth not byte-perfect: %q want %q", f.Files[pamSystemAuth], a)
	}
	if f.Files[pamPasswordAuth] != b { // pragma: allowlist secret  (PAM file path compare, not a secret)
		t.Errorf("password-auth not byte-perfect: %q want %q", f.Files[pamPasswordAuth], b)
	}
}

// pam_module_arg declares every captured file to the gate.
//
// @spec footprint-funnel
// @ac AC-04
// @spec handler-pam-module-arg
// @ac AC-07
func TestCapturedFootprint(t *testing.T) {
	t.Run("footprint-funnel/AC-04", func(t *testing.T) {})
	t.Run("handler-pam-module-arg/AC-07", func(t *testing.T) {})
	var fp footprint.Footprinter = pammodulearg.New()
	f, err := fp.CapturedFootprint(&api.PreState{Data: map[string]interface{}{
		"files_content": map[string]interface{}{pamSystemAuth: "x", pamPasswordAuth: "y"},
	}})
	if err != nil {
		t.Fatalf("CapturedFootprint: %v", err)
	}
	if f.Len() != 2 || !f.Has(pamSystemAuth) || !f.Has(pamPasswordAuth) {
		t.Errorf("footprint=%v want both PAM files", f.Entries())
	}
}

// A legacy pre-state (files_snapshot) still declares its files to the gate, so
// an in-flight transaction captured before the whole-file model gates too.
//
// @spec handler-pam-module-arg
// @ac AC-07
func TestCapturedFootprint_LegacySnapshot(t *testing.T) {
	t.Run("handler-pam-module-arg/AC-07", func(t *testing.T) {})
	var fp footprint.Footprinter = pammodulearg.New()
	f, err := fp.CapturedFootprint(&api.PreState{Data: map[string]interface{}{
		"files_snapshot": map[string]interface{}{pamSystemAuth: "5:auth pam_unix.so\n"},
	}})
	if err != nil {
		t.Fatalf("CapturedFootprint(legacy): %v", err)
	}
	if f.Len() != 1 || !f.Has(pamSystemAuth) {
		t.Errorf("legacy footprint=%v want %s", f.Entries(), pamSystemAuth)
	}
}
