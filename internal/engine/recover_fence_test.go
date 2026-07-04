package engine_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handler"
	"github.com/Hanalyx/kensa/internal/store"
)

// TestEngine_AC05_RecoverLockFencesLiveEngine locks the live-engine side of the
// recover fence (limit #14): an engine built WithRecoverLock takes the recover
// lock SHARED for a mutation, so a `kensa recover` holding it EXCLUSIVE gets a
// clean ErrRecoverActive instead of racing an in-flight transaction.
//
// @spec recovery-replay
// @ac AC-05
func TestEngine_AC05_RecoverLockFencesLiveEngine(t *testing.T) {
	t.Run("recovery-replay/AC-05", func(t *testing.T) {})
	t.Log("// @spec recovery-replay")
	t.Log("// @ac AC-05")

	lockPath := filepath.Join(t.TempDir(), "results.db.recover.lock")
	r := handler.NewRegistry()
	r.Register(&engine.FakeHandler{HandlerName: "fake_ok", IsCapturable: true})
	e := engine.New(engine.WithRegistry(r), engine.WithRecoverLock(lockPath))

	// A recover holding the EXCLUSIVE lock must fence both mutating entry points.
	excl, err := store.AcquireRecoverLock(lockPath, true)
	if err != nil {
		t.Fatalf("acquire exclusive recover lock: %v", err)
	}
	if _, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok"), false); !errors.Is(err, api.ErrRecoverActive) {
		t.Errorf("Run under an active recover: got %v, want api.ErrRecoverActive", err)
	}
	if _, err := e.RollbackTransaction(context.Background(), engine.NewFakeTransport(), &api.TransactionRecord{}); !errors.Is(err, api.ErrRecoverActive) {
		t.Errorf("RollbackTransaction under an active recover: got %v, want api.ErrRecoverActive", err)
	}

	// Fence lifts once the recover releases: Run proceeds (no ErrRecoverActive).
	if err := excl.Release(); err != nil {
		t.Fatalf("release exclusive: %v", err)
	}
	if _, err := e.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok"), false); errors.Is(err, api.ErrRecoverActive) {
		t.Error("Run after the recover released still returned ErrRecoverActive (fence did not lift)")
	}

	// A bare engine (no WithRecoverLock) is never fenced — the fence is opt-in
	// and wired only by the Default* constructors.
	excl2, err := store.AcquireRecoverLock(lockPath, true)
	if err != nil {
		t.Fatalf("re-acquire exclusive recover lock: %v", err)
	}
	defer func() { _ = excl2.Release() }()
	bare := engine.New(engine.WithRegistry(r))
	if _, err := bare.Run(context.Background(), engine.NewFakeTransport(), basicTxn("fake_ok"), false); errors.Is(err, api.ErrRecoverActive) {
		t.Error("bare engine (no WithRecoverLock) must not be fenced")
	}
}
