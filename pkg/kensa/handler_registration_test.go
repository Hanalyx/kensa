package kensa

import (
	"context"
	"testing"

	"github.com/Hanalyx/kensa/internal/handler"
)

// TestExternalConsumerHandlersRegistered is the issue-#94 regression
// guard. This test imports only pkg/kensa (no internal/handlers blank
// imports) — the way an external consumer must, since Go forbids
// importing another module's internal/ packages. The apply handlers must
// nonetheless be registered, because pkg/kensa blank-imports the
// pkg/kensa/handlers bundle. Before the fix, handler.Default() was empty
// for an external consumer and Remediate failed at preflight.
//
// @spec pkg-handler-registration
// @ac AC-01
func TestExternalConsumerHandlersRegistered(t *testing.T) {
	t.Run("pkg-handler-registration/AC-01", func(t *testing.T) {})

	for _, mech := range []string{"file_permissions", "config_set", "service_enabled"} {
		if _, ok := handler.Default().Get(mech); !ok {
			t.Errorf("mechanism %q not registered via a bare pkg/kensa import — Remediate would fail preflight for external consumers (issue #94)", mech)
		}
	}
}

// TestDefaultWithTransportFactory_RemediateHandlersPresent exercises the
// exact OpenWatch construction path: DefaultWithTransportFactory with a
// caller-supplied TransportFactory. The resulting service's engine reads
// handler.Default(); the apply handlers must be present so preflight does
// not reject a file_permissions step with "is not registered".
//
// @spec pkg-handler-registration
// @ac AC-02
func TestDefaultWithTransportFactory_RemediateHandlersPresent(t *testing.T) {
	t.Run("pkg-handler-registration/AC-02", func(t *testing.T) {})

	tf := &fakeFactory{}
	svc, err := DefaultWithTransportFactory(context.Background(), t.TempDir()+"/r.db", tf)
	if err != nil {
		t.Fatalf("DefaultWithTransportFactory: %v", err)
	}
	defer func() { _ = svc.Close() }()

	if _, ok := handler.Default().Get("file_permissions"); !ok {
		t.Fatal("file_permissions not registered after DefaultWithTransportFactory — Remediate would fail at preflight (issue #94)")
	}
}
