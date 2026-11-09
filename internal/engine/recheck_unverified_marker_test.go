package engine_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
)

// These cases state the typed unverified signal for a post-apply re-check,
// before the change that adds it. A re-check that could not read the host
// still commits (ERROR is not FAIL), and today the only sign of it is the
// word "unverified" in the validator Detail. The signal is an Unverified
// field on the validator result, mirrored on the transaction result. Neither
// field exists yet, so the cases read them through JSON.
//
// @spec engine-transaction
// @ac AC-18, AC-19, AC-20 (extended with the typed marker; the new criteria are not in the spec yet)

// strictTransport answers only the commands a test programmed, with output
// shaped like the real transport's (trailing newlines trimmed). Any other
// command is recorded and fails, so a case cannot pass on an answer nobody
// gave it.
type strictTransport struct {
	*engine.FakeTransport
	failOn     string
	mu         sync.Mutex
	unexpected []string
}

func (s *strictTransport) Run(ctx context.Context, cmd string) (*api.CommandResult, error) {
	if cmd == s.failOn {
		return nil, errInducedRecheck
	}
	if _, ok := s.Results[cmd]; !ok {
		s.mu.Lock()
		s.unexpected = append(s.unexpected, cmd)
		s.mu.Unlock()
		return &api.CommandResult{ExitCode: 127, Stderr: "sh: 1: " + cmd + ": not found"}, nil
	}
	return s.FakeTransport.Run(ctx, cmd)
}

var errInducedRecheck = errors.New("induced transport failure on re-check")

// jsonBool reads a top-level boolean key from v's JSON. present is false when
// the key does not exist.
func jsonBool(t *testing.T, v any, key string) (val, present bool) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	r, ok := m[key]
	if !ok {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(r, &b); err != nil {
		t.Fatalf("%s is not a boolean: %s", key, r)
	}
	return b, true
}

func runRecheck(t *testing.T, mechanism, cmd string, result *api.CommandResult, failOn string) (*api.TransactionResult, *strictTransport, *engine.FakeHandler) {
	t.Helper()
	h := &engine.FakeHandler{
		HandlerName:    mechanism,
		IsCapturable:   true,
		RollbackResult: &api.RollbackResult{Success: true},
	}
	e := durabilityEngine(t, nil, nil, h)
	tr := &strictTransport{FakeTransport: engine.NewFakeTransport(), failOn: failOn}
	if result != nil {
		tr.Results[cmd] = result
	}
	res, err := e.Run(context.Background(), tr, checkTxn(mechanism, cmd), false)
	if err != nil {
		t.Fatalf("Run returned err: %v", err)
	}
	if len(tr.unexpected) > 0 {
		t.Fatalf("the engine ran commands the test did not program: %q", tr.unexpected)
	}
	return res, tr, h
}

func TestRecheck_TypedUnverifiedMarker(t *testing.T) {
	t.Run("verified commits with no unverified marker", func(t *testing.T) {
		res, _, _ := runRecheck(t, "rcu_ok", "rcu-pass", &api.CommandResult{ExitCode: 0, Stdout: "ok"}, "")
		if res.Status != api.StatusCommitted {
			t.Fatalf("got %s, want committed", res.Status)
		}
		vr := recheckValidator(res.Envelope)
		if vr == nil || !vr.Passed {
			t.Fatalf("want a passing post-apply-recheck validator; got %+v", vr)
		}
		if v, _ := jsonBool(t, vr, "Unverified"); v {
			t.Error("a verified re-check carries Unverified=true")
		}
		if v, _ := jsonBool(t, res, "Unverified"); v {
			t.Error("a verified transaction carries Unverified=true")
		}
	})

	t.Run("unverified commits with a typed marker and unchanged detail", func(t *testing.T) {
		res, _, h := runRecheck(t, "rcu_err", "rcu-err", nil, "rcu-err")
		if res.Status != api.StatusCommitted {
			t.Fatalf("a re-check ERROR must still commit; got %s", res.Status)
		}
		if h.RollbackCalls != 0 {
			t.Fatalf("a re-check ERROR rolled back (%d calls)", h.RollbackCalls)
		}
		vr := recheckValidator(res.Envelope)
		if vr == nil || !vr.Passed {
			t.Fatalf("want Passed=true on the unverified re-check; got %+v", vr)
		}
		if !strings.HasPrefix(vr.Detail, "unverified: post-apply re-check could not read host state") {
			t.Errorf("the unverified Detail changed: %q", vr.Detail)
		}
		if v, ok := jsonBool(t, vr, "Unverified"); !ok || !v {
			t.Errorf("no typed marker on the validator result: Unverified present=%v value=%v; "+
				"only the Detail text says unverified", ok, v)
		}
		if v, ok := jsonBool(t, res, "Unverified"); !ok || !v {
			t.Errorf("the marker is not mirrored on the transaction result: Unverified present=%v value=%v", ok, v)
		}
	})

	t.Run("failed does not commit", func(t *testing.T) {
		res, _, _ := runRecheck(t, "rcu_fail", "rcu-fail", &api.CommandResult{ExitCode: 1, Stdout: "still wrong"}, "")
		if res.Status == api.StatusCommitted {
			t.Fatal("a re-check that read the host and failed committed")
		}
		vr := recheckValidator(res.Envelope)
		if vr == nil || vr.Passed {
			t.Fatalf("want a failing post-apply-recheck validator; got %+v", vr)
		}
		if v, _ := jsonBool(t, vr, "Unverified"); v {
			t.Error("a failed re-check carries Unverified=true")
		}
	})
}
