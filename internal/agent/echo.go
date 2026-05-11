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
// shutdown: returns nil) or ctx is cancelled (returns ctx.Err()).
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
// cmd/kensa/agent.go provides a 500ms grace-period forced
// os.Exit fallback for the SIGTERM-during-read case (Go's
// runtime poller is not reliable for waking blocked pipe Reads
// on Close from another goroutine).
func Run(ctx context.Context, r io.Reader, w io.Writer, stderr io.Writer, handler Handler) error {
	for {
		// Check ctx before each read so a cancellation that
		// arrives between frames preempts cleanly.
		if err := ctx.Err(); err != nil {
			return err
		}

		payload, err := Read(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Clean EOF between frames — controller closed
				// stdin. Per spec C-06, this is a successful
				// termination, not an error.
				return nil
			}
			fmt.Fprintf(stderr, "kensa agent: read frame from stdin: %v\n", err)
			return err
		}

		var req wirev1.Request
		if err := proto.Unmarshal(payload, &req); err != nil {
			fmt.Fprintf(stderr, "kensa agent: unmarshal Request: %v\n", err)
			return fmt.Errorf("unmarshal Request: %w", err)
		}

		resp := handler(&req)

		respBytes, err := proto.Marshal(resp)
		if err != nil {
			fmt.Fprintf(stderr, "kensa agent: marshal Response: %v\n", err)
			return fmt.Errorf("marshal Response: %w", err)
		}
		if err := Write(w, respBytes); err != nil {
			fmt.Fprintf(stderr, "kensa agent: write frame to stdout: %v\n", err)
			return err
		}
	}
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
