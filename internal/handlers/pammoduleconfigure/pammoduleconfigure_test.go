package pammoduleconfigure_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/pammoduleconfigure"
)

// @spec handler-pam-module-configure
// @spec handler-pam-module-configure
// @ac AC-01
// @spec handler-interface
// @ac AC-06
func TestApply_AddsPAMModuleLine(t *testing.T) {
	t.Run("handler-pam-module-configure/AC-01", func(t *testing.T) {})
	t.Run("handler-interface/AC-06", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := pammoduleconfigure.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"service": "sshd",
		"type":    "auth",
		"control": "required",
		"module":  "pam_faillock.so",
		"args":    "preauth silent deny=5",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	cmd := tp.Runs[0]
	if !strings.Contains(cmd, "pam_faillock.so") {
		t.Errorf("expected module in cmd; got %q", cmd)
	}
}

// @spec handler-pam-module-configure
// @ac AC-02
// @spec handler-interface
// @ac AC-02
func TestCapture_ReturnsErrCaptureIncompleteForMissingFile(t *testing.T) {
	t.Run("handler-pam-module-configure/AC-02", func(t *testing.T) {})
	t.Run("handler-interface/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	tp.Results["cat '/etc/pam.d/nonexistent'"] = &api.CommandResult{
		ExitCode: 1,
		Stderr:   "cat: /etc/pam.d/nonexistent: No such file or directory",
	}
	h := pammoduleconfigure.New()
	_, err := h.Capture(context.Background(), tp, api.Params{
		"service": "nonexistent", "type": "auth",
		"control": "required", "module": "pam_faillock.so",
	})
	if err == nil {
		t.Fatal("expected error for missing PAM file")
	}
	if !errors.Is(err, api.ErrCaptureIncomplete) {
		t.Errorf("got %v, want ErrCaptureIncomplete", err)
	}
}

// @spec handler-pam-module-configure
// @ac AC-03
// @spec handler-interface
// @ac AC-03
func TestRollback_RestoresPriorContent(t *testing.T) {
	t.Run("handler-pam-module-configure/AC-03", func(t *testing.T) {})
	t.Run("handler-interface/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := pammoduleconfigure.New()
	pre := &api.PreState{
		Data: map[string]interface{}{
			"service":       "sshd",
			"path":          "/etc/pam.d/sshd",
			"prior_content": "auth required pam_env.so\n",
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !strings.Contains(tp.Runs[0], "printf") {
		t.Errorf("expected printf restore; got %q", tp.Runs[0])
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = pammoduleconfigure.New()
}
