// L-008 agent loop. Reads framed wirev1.Request messages from
// stdin, hands each to a handler function (today: echo;
// L-009: real Apply/Capture/Rollback dispatcher), writes the
// resulting Response framed on stdout. Exits cleanly on stdin
// EOF or context cancellation.
//
// **Separability for L-009.** The loop body is intentionally
// split into Run() (framing + I/O + ctx) and handleEcho()
// (Request → Response logic). L-009's real dispatcher replaces
// `handleEcho` with a function that routes Request to the
// kensa.Engine; the framing / EOF / ctx / stderr machinery
// stays untouched. The handler signature
// (`func(*wirev1.Request) *wirev1.Response`) is the single
// extension point.

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// Handler routes a wirev1.Request to a Response. L-008 ships
// `handleEcho` as the only implementation; L-009 replaces it
// with the real Engine-backed dispatcher.
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
// stderr receives one human-readable diagnostic line per fatal
// error; the caller surfaces it to the operator.
//
// **Context cancellation.** ctx.Done() is checked between
// frames. A read blocked on a half-closed SSH pipe won't be
// preempted by ctx until the read either returns or completes.
// For the v1.0 stub this is acceptable — the controller side
// closes stdin to signal shutdown, which unblocks the read
// promptly. L-012 will add an explicit shutdown-message type so
// ctx cancellation doesn't depend on stdin closure.
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

// HandleEcho is L-008's stub Handler. Mirrors the Request's
// correlation_id and payload into a Response with the same
// schema_version. cmd/kensa/agent.go passes this to Run() today;
// L-009 will introduce a real handler (Engine-backed dispatcher
// for Apply / Capture / Rollback) and the CLI will switch the
// handler argument — Run itself stays unchanged.
func HandleEcho(req *wirev1.Request) *wirev1.Response {
	return &wirev1.Response{
		SchemaVersion: 1,
		CorrelationId: req.GetCorrelationId(),
		Payload:       req.GetPayload(),
	}
}
