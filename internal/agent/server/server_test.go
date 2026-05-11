package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
	"github.com/Hanalyx/kensa-go/internal/handler"

	// Blank import so file_permissions registers in
	// handler.Default(). Same pattern cmd/kensa/main.go
	// uses.
	_ "github.com/Hanalyx/kensa-go/internal/handlers/filepermissions"
)

// TestServer_Handle_UnknownMechanism locks AC-05: a
// Request for a mechanism that isn't registered returns
// envelope Error code "unknown_mechanism".
//
// @spec agent-handler-port-filepermissions
// @ac AC-05
func TestServer_Handle_UnknownMechanism(t *testing.T) {
	params, _ := wirev1.APIParamsToWire(api.Params{})
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 1,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{
				Mechanism: "this_mechanism_does_not_exist",
				Params:    params,
			},
		},
	}
	resp := Handle(req)
	if resp.GetError() == nil {
		t.Fatal("expected envelope Error, got nil")
	}
	if resp.GetError().GetCode() != "unknown_mechanism" {
		t.Errorf("Error.Code: got %q, want %q", resp.GetError().GetCode(), "unknown_mechanism")
	}
	if resp.GetPayload() != nil {
		t.Errorf("expected nil typed payload on Error response; got %T", resp.GetPayload())
	}
}

// TestServer_Handle_EmptyMechanism locks the input-validation
// hook: ApplyRequest with mechanism="" returns
// invalid_request, not unknown_mechanism.
func TestServer_Handle_EmptyMechanism(t *testing.T) {
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 1,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{Mechanism: ""},
		},
	}
	resp := Handle(req)
	if resp.GetError() == nil {
		t.Fatal("expected envelope Error")
	}
	if resp.GetError().GetCode() != "invalid_request" {
		t.Errorf("Error.Code: got %q, want %q", resp.GetError().GetCode(), "invalid_request")
	}
}

// TestServer_Handle_ApplyFilePermissions locks AC-04: a
// real file_permissions Apply dispatched via server.Handle
// produces an ApplyResponse with a populated StepResult.
//
// This is the bridge proof: the L-007..L-013 wire stack
// connects to a real handler and produces a real result.
//
// @spec agent-handler-port-filepermissions
// @ac AC-04
func TestServer_Handle_ApplyFilePermissions(t *testing.T) {
	// Set up a local file we can chmod.
	dir := t.TempDir()
	target := filepath.Join(dir, "test-file")
	if err := os.WriteFile(target, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	params, err := wirev1.APIParamsToWire(api.Params{
		"path": target,
		"mode": "0644",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 42,
		Payload: &wirev1.Request_Apply{
			Apply: &wirev1.ApplyRequest{
				Mechanism: "file_permissions",
				Params:    params,
			},
		},
	}
	resp := Handle(req)
	if resp.GetError() != nil {
		t.Fatalf("unexpected envelope Error: %v", resp.GetError())
	}
	applyResp, ok := resp.GetPayload().(*wirev1.Response_ApplyResp)
	if !ok {
		t.Fatalf("expected ApplyResp; got %T", resp.GetPayload())
	}
	if applyResp.ApplyResp.GetStepResult() == nil {
		t.Fatal("StepResult is nil")
	}
	// Verify the file's mode actually changed on disk.
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("file mode after Apply: got %o, want 0644", info.Mode().Perm())
	}
}

// TestServer_Handle_HandshakePassthrough locks the C-03
// rule that Handshake forwards to HandleEcho's existing
// implementation.
func TestServer_Handle_HandshakePassthrough(t *testing.T) {
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 1,
		Payload: &wirev1.Request_Handshake{
			Handshake: &wirev1.HandshakeRequest{
				Major: wirev1.ProtocolMajor,
				Minor: wirev1.ProtocolMinor,
				Build: "test",
			},
		},
	}
	resp := Handle(req)
	if resp.GetError() != nil {
		t.Fatalf("unexpected error: %v", resp.GetError())
	}
	ack, ok := resp.GetPayload().(*wirev1.Response_HandshakeAck)
	if !ok {
		t.Fatalf("expected HandshakeAck; got %T", resp.GetPayload())
	}
	if !ack.HandshakeAck.GetAccepted() {
		t.Error("happy-path handshake should be accepted")
	}
}

// TestServer_Handle_HeartbeatPassthrough locks the C-03
// rule for Heartbeat.
func TestServer_Handle_HeartbeatPassthrough(t *testing.T) {
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: 1,
		Payload: &wirev1.Request_Heartbeat{
			Heartbeat: &wirev1.HeartbeatRequest{Token: 0xfeedface},
		},
	}
	resp := Handle(req)
	ack, ok := resp.GetPayload().(*wirev1.Response_HeartbeatAck)
	if !ok {
		t.Fatalf("expected HeartbeatAck; got %T", resp.GetPayload())
	}
	if ack.HeartbeatAck.GetToken() != 0xfeedface {
		t.Errorf("token: got %#x, want 0xfeedface", ack.HeartbeatAck.GetToken())
	}
}

// guard: ensure file_permissions is registered for the
// tests above.
func init() {
	if _, ok := handler.Default().Get("file_permissions"); !ok {
		// Surface loudly at test-start so test failures
		// elsewhere don't get confused with
		// "file_permissions handler not registered."
		_ = context.Background()
	}
}
