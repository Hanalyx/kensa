// L-008 agent loop + L-009 type-aware echo handler. Reads
// framed wirev1.Request messages from stdin, hands each to a
// handler function (L-009: type-aware echo dispatching on the
// Request's oneof variant; L-011/L-014: real Engine-backed
// dispatcher), writes the resulting Response framed on stdout.
// Exits cleanly on stdin EOF or context cancellation.
//
// **Separability for L-011.** The loop body splits into Run()
// (framing + I/O + ctx) and a Handler function (Request →
// Response). L-011's real dispatcher replaces `HandleEcho` with
// a function that routes Request variants to the kensa.Engine;
// the framing / EOF / ctx / stderr machinery stays untouched.
//
// **L-011/L-014 dispatcher design notes** (so the future author
// doesn't rederive this):
//
//  1. **Local transport, not SSH.** When the dispatcher invokes
//     a handler's Apply/Capture/Rollback, the `transport`
//     argument is a LOCAL-syscall Transport — the agent IS the
//     target's local execution surface. SSH is the OUTER pipe
//     (controller → kensa agent --stdio); the handler never
//     sees it. L-011 will introduce an internal/agent/transport
//     package with a local-fs / local-exec Transport
//     implementation.
//  2. **Handler registry.** The agent binary blank-imports
//     `internal/handlers/*` (same pattern as cmd/kensa/main.go's
//     `_ "github.com/Hanalyx/kensa-go/internal/handlers/..."`)
//     so handler.Default() is populated at startup. The
//     dispatcher looks up `Apply.GetMechanism()` against
//     handler.Default().Get(mechanism) and rejects with an
//     envelope Error if the mechanism is unknown.
//  3. **Error dispatch.** Apply/Capture/Rollback return
//     `(result, error)`. (result, nil) → typed Response. (nil,
//     err) → Response with envelope-level Error (code +
//     detail) and no typed payload — the controller treats
//     "no typed payload + Error set" as "handler couldn't run."
//     (failed-result, nil) → typed Response carrying the result
//     with Success=false + Detail set — that's "handler ran
//     but the action failed."
//  4. **Input validation.** proto3 has no required fields. The
//     dispatcher MUST validate `Apply.GetMechanism() != ""`,
//     `Rollback.GetPreState() != nil`, etc. before dispatch.
//     Validation failures → envelope Error with code
//     "invalid_request".

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// Handler routes a wirev1.Request to a Response. L-009 ships
// HandleEcho as the only implementation; L-011/L-014 replace
// it with the real Engine-backed dispatcher.
type Handler func(*wirev1.Request) *wirev1.Response

// Run reads frames from r, hands each Request to handler, writes
// the framed Response on w, until r returns io.EOF (clean
// shutdown: returns nil) or ctx is canceled (returns ctx.Err()).
//
// Errors that terminate the loop with a non-nil return:
//   - framing error (oversized frame, truncated payload, unreadable stream)
//   - protobuf unmarshal error (peer sent garbage)
//   - protobuf marshal error (extremely unlikely; bug in handler)
//   - write error on w (downstream pipe closed)
//
// **Context cancellation.** ctx.Done() is checked between
// frames. A read blocked on a half-closed SSH pipe won't be
// preempted by ctx until the read either returns or completes.
// The cmd/kensa/agent.go entrypoint provides a 500ms
// grace-period forced os.Exit fallback for the
// SIGTERM-during-read case (Go's
// runtime poller is not reliable for waking blocked pipe Reads
// on Close from another goroutine).
// Validator inspects a decoded Request and returns an error
// for protocol violations. The L-009/L-010 default is
// wirev1.ValidateRequest (multi-variant oneof guard). L-011's
// dispatcher composes this with mechanism-name + nil-PreState
// checks. Tests inject custom validators to exercise the
// envelope-Error-on-validation-failure code path that
// real wire bytes cannot reach (protobuf-go's Unmarshal
// collapses multi-variant before validation sees it).
type Validator func(*wirev1.Request) error

// Run drives the agent loop with the default validator
// (wirev1.ValidateRequest). Equivalent to
// RunWithValidator(ctx, r, w, stderr, handler,
// wirev1.ValidateRequest).
func Run(ctx context.Context, r io.Reader, w io.Writer, stderr io.Writer, handler Handler) error {
	return RunWithValidator(ctx, r, w, stderr, handler, wirev1.ValidateRequest)
}

// RunWithValidator is Run with an explicit Validator. L-011's
// dispatcher uses this to inject mechanism-name + nil-PreState
// + dispatcher-specific checks alongside the default wirev1
// guard. Tests inject failure-forcing validators to exercise
// the envelope-Error path.
func RunWithValidator(ctx context.Context, r io.Reader, w io.Writer, stderr io.Writer, handler Handler, validate Validator) error {
	for {
		// Check ctx before each read so a cancellation that
		// arrives between frames preempts cleanly.
		if err := ctx.Err(); err != nil {
			return err
		}

		frameType, payload, err := Read(r, nil)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Clean EOF between frames — controller closed
				// stdin. Per spec C-06, this is a successful
				// termination, not an error.
				return nil
			}
			fmt.Fprintf(stderr, "kensa agent: decode: read frame: %v\n", err)
			return err
		}
		// Future frame types (L-012 FrameHeartbeat, etc.)
		// land here. For L-010 only FramePayload is handled;
		// any other recognized type means a future kensa
		// build sent a frame this build doesn't route. Read
		// already rejects unknown types via ErrUnknownFrameType,
		// so reaching this branch with a non-Payload type
		// means knownFrameTypes was extended without updating
		// Run's dispatch — that's a build-time bug.
		if frameType != FramePayload {
			fmt.Fprintf(stderr, "kensa agent: frame type 0x%02x recognized but not routed (extend Run's dispatch)\n", byte(frameType))
			return fmt.Errorf("unrouted frame type 0x%02x", byte(frameType))
		}

		var req wirev1.Request
		if err := proto.Unmarshal(payload, &req); err != nil {
			fmt.Fprintf(stderr, "kensa agent: decode: peer sent invalid protobuf payload in frame type 0x01: %v\n", err)
			return fmt.Errorf("unmarshal Request: %w", err)
		}

		// L-010 validation guard. On rejection, surface an
		// envelope-level Error to the controller and continue
		// the loop — per-frame protocol violation, not a
		// fatal stream error.
		if err := validate(&req); err != nil {
			fmt.Fprintf(stderr, "kensa agent: invalid Request: %v\n", err)
			errResp := &wirev1.Response{
				SchemaVersion: req.GetSchemaVersion(),
				CorrelationId: req.GetCorrelationId(),
				Error: &wirev1.Error{
					SchemaVersion: 1,
					Code:          "invalid_request",
					Detail:        err.Error(),
					Retryable:     false,
				},
			}
			if err := writeResponse(w, errResp, stderr); err != nil {
				return err
			}
			continue
		}

		resp := handler(&req)
		if err := writeResponse(w, resp, stderr); err != nil {
			return err
		}
	}
}

// writeResponse marshals + frame-writes a Response. Extracted
// from Run so the validation-failure path and the
// happy-path can share the same encoding logic.
//
// Server-side ValidateResponse guard: catches a dispatcher
// bug where two payload oneof variants were set on the same
// Response (the only realistic firing condition for the
// multi-variant guard, since protobuf-go's Unmarshal collapses
// multi-variant on the incoming side). On guard failure, the
// agent returns the error to Run — the loop terminates with
// the marshal-error path because shipping a malformed
// Response is worse than dying.
func writeResponse(w io.Writer, resp *wirev1.Response, stderr io.Writer) error {
	if err := wirev1.ValidateResponse(resp); err != nil {
		fmt.Fprintf(stderr, "kensa agent: encode: dispatcher built invalid Response: %v\n", err)
		return fmt.Errorf("validate Response: %w", err)
	}
	respBytes, err := proto.Marshal(resp)
	if err != nil {
		fmt.Fprintf(stderr, "kensa agent: encode: marshal Response: %v\n", err)
		return fmt.Errorf("marshal Response: %w", err)
	}
	if err := Write(w, FramePayload, respBytes, nil); err != nil {
		fmt.Fprintf(stderr, "kensa agent: encode: write frame to stdout: %v\n", err)
		return err
	}
	return nil
}

// HandleEcho is L-009's type-aware stub Handler. Dispatches on
// the Request's oneof variant and returns a Response whose
// variant matches:
//
//	ApplyRequest      → ApplyResponse with empty step_result
//	CaptureRequest    → CaptureResponse with empty pre_state
//	RollbackRequest   → RollbackResponse with empty rollback_result
//	HeartbeatRequest  → HeartbeatAck (token echoed exactly so
//	                    the controller can pair acks)
//	(unset payload)   → Response with Error envelope explaining
//	                    the missing variant
//
// schema_version + correlation_id are mirrored from Request to
// Response on every variant. Detail-level fields are
// default-valued (empty strings, false booleans) — the echo's
// job is schema-roundtrip validation, not faithful invocation.
//
// L-011/L-014 replaces this with the real Engine-backed
// dispatcher.
func HandleEcho(req *wirev1.Request) *wirev1.Response {
	resp := &wirev1.Response{
		SchemaVersion: req.GetSchemaVersion(),
		CorrelationId: req.GetCorrelationId(),
	}
	switch p := req.GetPayload().(type) {
	case *wirev1.Request_Apply:
		resp.Payload = &wirev1.Response_ApplyResp{
			ApplyResp: &wirev1.ApplyResponse{
				StepResult: &wirev1.WireStepResult{},
			},
		}
	case *wirev1.Request_Capture:
		resp.Payload = &wirev1.Response_CaptureResp{
			CaptureResp: &wirev1.CaptureResponse{
				PreState: &wirev1.WirePreState{},
			},
		}
	case *wirev1.Request_Rollback:
		resp.Payload = &wirev1.Response_RollbackResp{
			RollbackResp: &wirev1.RollbackResponse{
				RollbackResult: &wirev1.WireRollbackResult{},
			},
		}
	case *wirev1.Request_Heartbeat:
		// Token echo MUST be exact (C-06) so the controller
		// can pair HeartbeatAck with the right outstanding
		// HeartbeatRequest. received_unix_micros is the
		// agent's local clock at receipt-time; advisory only.
		resp.Payload = &wirev1.Response_HeartbeatAck{
			HeartbeatAck: &wirev1.HeartbeatAck{
				Token:              p.Heartbeat.GetToken(),
				ReceivedUnixMicros: p.Heartbeat.GetSentUnixMicros(),
			},
		}
	case *wirev1.Request_Handshake:
		// L-012 version-handshake response. Build a
		// HandshakeAck with this build's protocol identity;
		// accepted=true iff the controller's major matches
		// ours. Minor mismatch is accepted (controller logs
		// a warning).
		compat, _ := wirev1.Compatible(p.Handshake.GetMajor(), p.Handshake.GetMinor())
		ack := &wirev1.HandshakeAck{
			Major:    wirev1.ProtocolMajor,
			Minor:    wirev1.ProtocolMinor,
			Build:    wirev1.ProtocolBuild,
			Accepted: compat,
		}
		if !compat {
			ack.Reason = fmt.Sprintf("protocol major mismatch: client=%d.%d, agent=%d.%d",
				p.Handshake.GetMajor(), p.Handshake.GetMinor(),
				wirev1.ProtocolMajor, wirev1.ProtocolMinor)
		}
		resp.Payload = &wirev1.Response_HandshakeAck{HandshakeAck: ack}
	default:
		// Request with no payload variant set (nil from
		// GetPayload, which protobuf-go returns when no oneof
		// case is selected on the wire — including the case
		// of an unknown future-variant the local build's
		// .pb.go doesn't define). Return an envelope-level
		// Error so the controller sees a diagnosable response
		// rather than a silently-empty Response.
		resp.Error = &wirev1.Error{
			SchemaVersion: 1,
			Code:          "unknown_payload_variant",
			Detail:        "Request.payload oneof is unset or this build does not recognize the variant",
			Retryable:     false,
		}
	}
	return resp
}
