// Agent-side handler dispatcher. L-014 deliverable per spec
// agent-handler-port-filepermissions C-03 (Option D2 from
// the design doc).
//
// **What this does.** Replaces L-009's `agent.HandleEcho`
// as the real handler router when `kensa agent --stdio` is
// running in production mode. Receives Apply / Capture /
// Rollback Requests, looks up the mechanism in
// `handler.Default()`, dispatches via a LocalTransport,
// wraps results.
//
// **What it does NOT do.**
//   - Replace HandleEcho entirely. HandleEcho stays as the
//     test fixture for wire-roundtrip validation; the real
//     dispatcher (this package) is what `kensa agent
//     --stdio` invokes in production.
//   - Run handlers. It DELEGATES to handler.Default()
//     entries; the handlers' code is unchanged.
//   - Implement input validation beyond the basics
//     (mechanism non-empty, PreState non-nil for Rollback).
//     The protobuf-level guards from L-010 fire upstream.
//
// **Handshake + Heartbeat pass-through.** Both forward to
// HandleEcho's existing logic since neither involves a
// kensa handler — Handshake is a protocol-level negotiation,
// Heartbeat is liveness. server.Handle dispatches Apply /
// Capture / Rollback; everything else falls through to the
// echo path.

package server

import (
	"context"
	"fmt"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent"
	"github.com/Hanalyx/kensa-go/internal/agent/deadman"
	"github.com/Hanalyx/kensa-go/internal/agent/transport/local"
	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
	"github.com/Hanalyx/kensa-go/internal/handler"
)

// Handle is the agent's typed Request → Response dispatcher.
// Satisfies the `agent.Handler` function type so `kensa
// agent --stdio` invokes it via `agent.Run(ctx, stdin,
// stdout, stderr, server.Handle)`.
//
// Dispatch rules per spec C-03:
//   - Apply / Capture / Rollback → handler.Default().Get,
//     construct LocalTransport, dispatch, wrap result
//   - Handshake / Heartbeat → agent.HandleEcho passthrough
//   - Unknown mechanism → envelope Error code "unknown_mechanism"
//   - Handler returned error → envelope Error code "handler_error"
//   - Capturable-handler-but-not-CaptureHandler → envelope
//     Error code "not_capturable" (defensive — registry
//     consistency should prevent this)
func Handle(req *wirev1.Request) *wirev1.Response {
	resp := &wirev1.Response{
		SchemaVersion: req.GetSchemaVersion(),
		CorrelationId: req.GetCorrelationId(),
	}
	switch p := req.GetPayload().(type) {
	case *wirev1.Request_Apply:
		dispatchApply(p.Apply, resp)
	case *wirev1.Request_Capture:
		dispatchCapture(p.Capture, resp)
	case *wirev1.Request_Rollback:
		dispatchRollback(p.Rollback, resp)
	case *wirev1.Request_ArmDeadman:
		dispatchArmDeadman(p.ArmDeadman, resp)
	case *wirev1.Request_CancelDeadman:
		dispatchCancelDeadman(p.CancelDeadman, resp)
	case *wirev1.Request_Handshake, *wirev1.Request_Heartbeat:
		// Pass through to the existing echo handler — it
		// already implements the L-012 handshake response
		// and the L-009 heartbeat token-mirror correctly.
		return agent.HandleEcho(req)
	default:
		resp.Error = &wirev1.Error{
			SchemaVersion: 1,
			Code:          "unknown_payload_variant",
			Detail:        "agent server received Request with no recognized payload variant",
		}
	}
	return resp
}

// **Carry-forward TODOs from L-014 review.**
//
// 1. **Synchronous dispatch blocks heartbeat path.** The
//    agent.Run loop processes one frame at a time; a
//    long-running Apply (apt-get, systemctl on slow
//    services) blocks the heartbeat channel. Future kensa
//    deliverable: spawn the handler invocation in a
//    goroutine, write Responses with a mutex on stdout so
//    heartbeat replies can interleave. Flag for L-015 prereq.
//
// 2. **Request context not propagated.** dispatchApply
//    builds `context.Background()` for the handler call,
//    discarding any deadline the controller set on its
//    client.Apply call. ApplyRequest needs a deadline_unix_micros
//    field, decoder needs to construct context.WithDeadline.
//    Flag for L-014b / L-015.
//
// 3. **Mismatched-agent rollback.** A RollbackRequest for a
//    mechanism the agent doesn't know typically means the
//    agent was restarted with a different binary mid-
//    session. The current error is "unknown_mechanism"
//    which is correct but opaque. Operators see a generic
//    Rollback failure with no specific guidance to inspect
//    the target. Flag for L-014b operator-docs.
//
// dispatchApply looks up the mechanism's handler, builds a
// LocalTransport, runs Apply, populates resp with either
// the ApplyResponse or an envelope Error.
func dispatchApply(req *wirev1.ApplyRequest, resp *wirev1.Response) {
	mechanism := req.GetMechanism()
	if mechanism == "" {
		setError(resp, "invalid_request", "ApplyRequest.mechanism is empty")
		return
	}
	h, ok := handler.Default().Get(mechanism)
	if !ok {
		setError(resp, "unknown_mechanism", fmt.Sprintf("no handler registered for mechanism %q", mechanism))
		return
	}

	params, err := wirev1.WireParamsToAPI(req.GetParams())
	if err != nil {
		setError(resp, "invalid_request", fmt.Sprintf("decode params: %v", err))
		return
	}
	var pre *api.PreState
	if req.GetPreState() != nil {
		decodedPre, err := wirev1.WirePreStateToAPI(req.GetPreState())
		if err != nil {
			setError(resp, "invalid_request", fmt.Sprintf("decode preState: %v", err))
			return
		}
		pre = &decodedPre
	}

	// Local transport — no SSH; agent IS the target.
	// NewAuto enables sudo iff the agent process is NOT
	// running as root. Production SSH users are typically
	// non-root; handlers needing privilege get wrapped
	// automatically. Per L-014 review fix.
	tr := local.NewAuto()
	defer tr.Close()

	sr, err := h.Apply(context.Background(), tr, params, pre)
	if err != nil {
		// Handler-returned error: convention from L-009
		// package doc — wrap as envelope Error.
		setError(resp, "handler_error", fmt.Sprintf("Apply(%s): %v", mechanism, err))
		return
	}
	if sr == nil {
		setError(resp, "handler_error", fmt.Sprintf("Apply(%s) returned nil StepResult", mechanism))
		return
	}
	resp.Payload = &wirev1.Response_ApplyResp{
		ApplyResp: &wirev1.ApplyResponse{
			StepResult: wirev1.APIStepResultToWire(*sr),
		},
	}
}

// dispatchCapture mirrors dispatchApply for capturable
// handlers' pre-state recording.
func dispatchCapture(req *wirev1.CaptureRequest, resp *wirev1.Response) {
	mechanism := req.GetMechanism()
	if mechanism == "" {
		setError(resp, "invalid_request", "CaptureRequest.mechanism is empty")
		return
	}
	h, ok := handler.Default().Get(mechanism)
	if !ok {
		setError(resp, "unknown_mechanism", fmt.Sprintf("no handler registered for mechanism %q", mechanism))
		return
	}
	ch, ok := h.(api.CaptureHandler)
	if !ok {
		setError(resp, "not_capturable",
			fmt.Sprintf("handler %q does not implement CaptureHandler", mechanism))
		return
	}

	params, err := wirev1.WireParamsToAPI(req.GetParams())
	if err != nil {
		setError(resp, "invalid_request", fmt.Sprintf("decode params: %v", err))
		return
	}

	// NewAuto enables sudo iff the agent process is NOT
	// running as root. Production SSH users are typically
	// non-root; handlers needing privilege get wrapped
	// automatically. Per L-014 review fix.
	tr := local.NewAuto()
	defer tr.Close()

	pre, err := ch.Capture(context.Background(), tr, params)
	if err != nil {
		setError(resp, "handler_error", fmt.Sprintf("Capture(%s): %v", mechanism, err))
		return
	}
	if pre == nil {
		setError(resp, "handler_error", fmt.Sprintf("Capture(%s) returned nil PreState", mechanism))
		return
	}
	wirePre, err := wirev1.APIPreStateToWire(*pre)
	if err != nil {
		setError(resp, "handler_error", fmt.Sprintf("encode PreState: %v", err))
		return
	}
	resp.Payload = &wirev1.Response_CaptureResp{
		CaptureResp: &wirev1.CaptureResponse{
			PreState: wirePre,
		},
	}
}

// dispatchRollback dispatches to the RollbackHandler. The
// Request's PreState is the captured state to restore.
func dispatchRollback(req *wirev1.RollbackRequest, resp *wirev1.Response) {
	if req.GetPreState() == nil {
		setError(resp, "invalid_request", "RollbackRequest.pre_state is nil")
		return
	}
	pre, err := wirev1.WirePreStateToAPI(req.GetPreState())
	if err != nil {
		setError(resp, "invalid_request", fmt.Sprintf("decode preState: %v", err))
		return
	}

	h, ok := handler.Default().Get(pre.Mechanism)
	if !ok {
		setError(resp, "unknown_mechanism", fmt.Sprintf("no handler registered for mechanism %q", pre.Mechanism))
		return
	}
	rh, ok := h.(api.RollbackHandler)
	if !ok {
		setError(resp, "not_capturable",
			fmt.Sprintf("handler %q does not implement RollbackHandler", pre.Mechanism))
		return
	}

	// NewAuto enables sudo iff the agent process is NOT
	// running as root. Production SSH users are typically
	// non-root; handlers needing privilege get wrapped
	// automatically. Per L-014 review fix.
	tr := local.NewAuto()
	defer tr.Close()

	rr, err := rh.Rollback(context.Background(), tr, &pre)
	if err != nil {
		setError(resp, "handler_error", fmt.Sprintf("Rollback(%s): %v", pre.Mechanism, err))
		return
	}
	if rr == nil {
		setError(resp, "handler_error", fmt.Sprintf("Rollback(%s) returned nil RollbackResult", pre.Mechanism))
		return
	}
	resp.Payload = &wirev1.Response_RollbackResp{
		RollbackResp: &wirev1.RollbackResponse{
			RollbackResult: wirev1.APIRollbackResultToWire(*rr),
		},
	}
}

// setError populates resp.Error with the given code +
// detail. Clears any typed payload to maintain the spec C-02
// envelope-takes-precedence semantics.
func setError(resp *wirev1.Response, code, detail string) {
	resp.Error = &wirev1.Error{
		SchemaVersion: 1,
		Code:          code,
		Detail:        detail,
		Retryable:     false,
	}
	resp.Payload = nil
}

// dispatchArmDeadman handles an ArmDeadmanRequest by
// delegating to the package-level deadman.Armer singleton.
// D-005 deliverable.
func dispatchArmDeadman(req *wirev1.ArmDeadmanRequest, resp *wirev1.Response) {
	if req.GetTxnId() == "" {
		setError(resp, "invalid_request", "ArmDeadmanRequest.txn_id is empty")
		return
	}
	if req.GetWindowSeconds() <= 0 {
		setError(resp, "invalid_request", fmt.Sprintf("ArmDeadmanRequest.window_seconds must be positive: %d", req.GetWindowSeconds()))
		return
	}
	firesAt, err := deadman.HandleArmDeadman(
		req.GetTxnId(),
		req.GetWindowSeconds(),
		req.GetRollbackCommands(),
	)
	if err != nil {
		setError(resp, "arm_deadman_failed", err.Error())
		return
	}
	resp.Payload = &wirev1.Response_ArmDeadmanResp{
		ArmDeadmanResp: &wirev1.ArmDeadmanResponse{
			FiresAt: firesAt,
		},
	}
}

// dispatchCancelDeadman handles a CancelDeadmanRequest.
func dispatchCancelDeadman(req *wirev1.CancelDeadmanRequest, resp *wirev1.Response) {
	if req.GetTxnId() == "" {
		setError(resp, "invalid_request", "CancelDeadmanRequest.txn_id is empty")
		return
	}
	wasActive := deadman.HandleCancelDeadman(req.GetTxnId())
	resp.Payload = &wirev1.Response_CancelDeadmanResp{
		CancelDeadmanResp: &wirev1.CancelDeadmanResponse{
			WasActive: wasActive,
		},
	}
}
