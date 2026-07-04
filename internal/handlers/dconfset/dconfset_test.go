package dconfset_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/dconfset"
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

// @spec handler-dconf-set
// @ac AC-01
func TestApply_WritesSnippetAndUpdates(t *testing.T) {
	t.Run("handler-dconf-set/AC-01", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := dconfset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"schema": "org/gnome/desktop/screensaver",
		"key":    "lock-enabled",
		"value":  "true",
		"file":   "00-security",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// Snippet written to /etc/dconf/db/local.d/00-security with the
	// [schema]/key=value content.
	if !anyRunContains(tp.Runs, "printf", "/etc/dconf/db/local.d/00-security") {
		t.Errorf("expected a snippet write; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "[org/gnome/desktop/screensaver]", "lock-enabled=true") {
		t.Errorf("expected snippet content with schema/key/value; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "dconf update") {
		t.Errorf("expected `dconf update`; runs=%v", tp.Runs)
	}
}

// @spec handler-dconf-set
// @ac AC-02
func TestApply_LockWritesLockFile(t *testing.T) {
	t.Run("handler-dconf-set/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := dconfset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"schema": "org/gnome/desktop/screensaver",
		"key":    "lock-enabled",
		"value":  "true",
		"file":   "00-security",
		"lock":   true,
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// locks dir created and a lock entry for /<schema>/<key> written.
	if !anyRunContains(tp.Runs, "mkdir -p", "/etc/dconf/db/local.d/locks") {
		t.Errorf("expected locks dir mkdir; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "/etc/dconf/db/local.d/locks/00-security") {
		t.Errorf("expected lock file write; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "/org/gnome/desktop/screensaver/lock-enabled") {
		t.Errorf("expected lock entry for /schema/key; runs=%v", tp.Runs)
	}
}

// @spec handler-dconf-set
// @ac AC-03
func TestApply_ValueTypeWrapsValue(t *testing.T) {
	t.Run("handler-dconf-set/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := dconfset.New()
	res, err := h.Apply(context.Background(), tp, api.Params{
		"schema":     "org/gnome/desktop/session",
		"key":        "idle-delay",
		"value":      "300",
		"file":       "00-security",
		"value_type": "uint32",
	}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "idle-delay=uint32(300)") {
		t.Errorf("expected value wrapped as uint32(300); runs=%v", tp.Runs)
	}
}

// @spec handler-dconf-set
// @ac AC-04
// @spec handler-interface
// @ac AC-02
func TestCapture_RecordsPriorContent(t *testing.T) {
	t.Run("handler-dconf-set/AC-04", func(t *testing.T) {})
	t.Run("handler-interface/AC-02", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	checkCmd := `if [ -f '/etc/dconf/db/local.d/00-security' ]; then base64 '/etc/dconf/db/local.d/00-security'; else printf '__KENSA_ABSENT__'; fi`
	tp.Results[checkCmd] = &api.CommandResult{Stdout: base64.StdEncoding.EncodeToString([]byte("[org/gnome/desktop/screensaver]\nlock-enabled=false\n"))}
	h := dconfset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"schema": "org/gnome/desktop/screensaver",
		"key":    "lock-enabled",
		"value":  "true",
		"file":   "00-security",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if got, _ := pre.Data["file_path"].(string); got != "/etc/dconf/db/local.d/00-security" {
		t.Errorf("file_path = %q", got)
	}
	if existed, _ := pre.Data["file_existed"].(bool); !existed {
		t.Errorf("file_existed = false, want true")
	}
	if got, _ := pre.Data["prior_content"].(string); !strings.Contains(got, "lock-enabled=false") {
		t.Errorf("prior_content did not record snippet; got %q", got)
	}
}

// @spec handler-dconf-set
// @ac AC-05
func TestCapture_RecordsAbsent(t *testing.T) {
	t.Run("handler-dconf-set/AC-05", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	checkCmd := `if [ -f '/etc/dconf/db/local.d/00-security' ]; then base64 '/etc/dconf/db/local.d/00-security'; else printf '__KENSA_ABSENT__'; fi`
	tp.Results[checkCmd] = &api.CommandResult{Stdout: "__KENSA_ABSENT__"}
	h := dconfset.New()
	pre, err := h.Capture(context.Background(), tp, api.Params{
		"schema": "org/gnome/desktop/screensaver",
		"key":    "lock-enabled",
		"value":  "true",
		"file":   "00-security",
	})
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if existed, _ := pre.Data["file_existed"].(bool); existed {
		t.Errorf("file_existed = true, want false")
	}
	if got, _ := pre.Data["prior_content"].(string); got != "" {
		t.Errorf("prior_content = %q, want empty", got)
	}
}

// @spec handler-dconf-set
// @ac AC-06
// @spec handler-interface
// @ac AC-03
func TestRollback_RestoresPriorContent(t *testing.T) {
	t.Run("handler-dconf-set/AC-06", func(t *testing.T) {})
	t.Run("handler-interface/AC-03", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := dconfset.New()
	pre := &api.PreState{
		Mechanism:  "dconf_set",
		Capturable: true,
		Data: map[string]interface{}{
			"file_path":     "/etc/dconf/db/local.d/00-security",
			"prior_content": "[org/gnome/desktop/screensaver]\nlock-enabled=false\n",
			"file_existed":  true,
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	// Restore writes the prior content back to the file (printf > file),
	// then re-runs dconf update.
	if !anyRunContains(tp.Runs, "printf", "/etc/dconf/db/local.d/00-security") {
		t.Errorf("expected a restore write; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "lock-enabled=false") {
		t.Errorf("expected prior content restored; runs=%v", tp.Runs)
	}
	if !anyRunContains(tp.Runs, "dconf update") {
		t.Errorf("expected `dconf update` on rollback; runs=%v", tp.Runs)
	}
}

// @spec handler-dconf-set
// @ac AC-07
func TestRollback_RemovesWhenAbsent(t *testing.T) {
	t.Run("handler-dconf-set/AC-07", func(t *testing.T) {})
	tp := engine.NewFakeTransport()
	h := dconfset.New()
	pre := &api.PreState{
		Mechanism:  "dconf_set",
		Capturable: true,
		Data: map[string]interface{}{
			"file_path":     "/etc/dconf/db/local.d/00-security",
			"prior_content": "",
			"file_existed":  false,
		},
	}
	res, err := h.Rollback(context.Background(), tp, pre)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Success {
		t.Errorf("Success=false: %s", res.Detail)
	}
	if !anyRunContains(tp.Runs, "rm -f", "/etc/dconf/db/local.d/00-security") {
		t.Errorf("expected the snippet removed; runs=%v", tp.Runs)
	}
}

// @spec handler-dconf-set
// @ac AC-08
func TestDecodeParams_RejectsInvalid(t *testing.T) {
	t.Run("handler-dconf-set/AC-08", func(t *testing.T) {})
	h := dconfset.New()
	cases := []struct {
		name   string
		params api.Params
	}{
		{"missing schema", api.Params{"key": "k", "value": "v", "file": "f"}},
		{"missing key", api.Params{"schema": "s", "value": "v", "file": "f"}},
		{"missing value", api.Params{"schema": "s", "key": "k", "file": "f"}},
		{"missing file", api.Params{"schema": "s", "key": "k", "value": "v"}},
		{"empty db", api.Params{"schema": "s", "key": "k", "value": "v", "file": "f", "db": ""}},
		{"bad lock type", api.Params{"schema": "s", "key": "k", "value": "v", "file": "f", "lock": "yes"}},
		{"bad value_type", api.Params{"schema": "s", "key": "k", "value": "v", "file": "f", "value_type": 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.Apply(context.Background(), engine.NewFakeTransport(), tc.params, nil); err == nil {
				t.Errorf("expected error for %q", tc.name)
			}
		})
	}
}

// @spec handler-dconf-set
// @ac AC-09
func TestRollback_RejectsNilPreState(t *testing.T) {
	t.Run("handler-dconf-set/AC-09", func(t *testing.T) {})
	h := dconfset.New()
	if _, err := h.Rollback(context.Background(), engine.NewFakeTransport(), nil); err == nil {
		t.Errorf("expected error on nil pre-state")
	}
	// pre-state present but missing file_path.
	pre := &api.PreState{Mechanism: "dconf_set", Data: map[string]interface{}{"file_existed": true}}
	if _, err := h.Rollback(context.Background(), engine.NewFakeTransport(), pre); err == nil {
		t.Errorf("expected error on pre-state missing file_path")
	}
}

// @spec handler-interface
// @ac AC-04
func TestHandler_SatisfiesCombinedHandler(t *testing.T) {
	t.Log("// @spec handler-interface")
	t.Log("// @ac AC-04")
	var _ api.CombinedHandler = dconfset.New()
}
