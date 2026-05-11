// Controller-side AgentClient. Speaks the L-009 typed wire
// protocol over the L-010 framing to a kensa agent process.
// L-011 deliverable per spec agent-client.
//
// **Lifecycle.** Caller wires the SSH-subprocess plumbing
// (`exec.Command("ssh", host, "kensa", "agent", "--stdio")`)
// and passes the StdinPipe + StdoutPipe to Open. The reader
// goroutine drains stdout and routes Responses by
// correlation_id. Close terminates the reader and rejects
// in-flight calls.
//
// **What this is NOT.** Not an api.Transport implementation.
// api.Transport is the shell-exec/file-transfer abstraction
// used by direct-SSH handlers. AgentClient is a parallel,
// typed-RPC client used by L-014's RemoteHandler shim.
//
// **Concurrency.** AgentClient is safe for concurrent use by
// multiple goroutines per spec C-07. The frame writer is
// mutex-guarded; the correlation map is RWMutex-protected.

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent"
	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// Sentinel errors callers can match via errors.Is.
var (
	// ErrClientClosed is returned from in-flight calls when
	// Close fires before their Response arrives, and from
	// new calls after Close completes.
	ErrClientClosed = errors.New("client: agent client closed")

	// ErrAgent is the sentinel for envelope-level Error
	// Responses. Use errors.Is(err, ErrAgent) to detect
	// agent-reported failures; errors.As to *AgentError to
	// extract Code / Detail / Retryable.
	ErrAgent = errors.New("client: agent returned error envelope")

	// ErrVariantMismatch fires when a Response's payload
	// variant doesn't match the Request's variant (e.g.,
	// Capture returned ApplyResponse). Indicates an
	// agent-side dispatcher bug.
	ErrVariantMismatch = errors.New("client: response variant does not match request variant")

	// ErrAgentStreamClosed is returned from in-flight calls
	// when the agent's stdout returns EOF or any read error
	// while the call was pending. Without this, an agent
	// crash mid-Apply would hang the call until ctx-timeout
	// (per-Apply timeouts are often minutes; the loud
	// fail-fast is preferable). The Unwrap'd cause is the
	// underlying read error (typically io.EOF).
	ErrAgentStreamClosed = errors.New("client: agent stream closed mid-call")
)

// AgentError carries the envelope Error fields. Callers
// use `errors.As(err, &agentErr)` to extract structured
// failure info.
type AgentError struct {
	Code      string
	Detail    string
	Retryable bool
}

func (e *AgentError) Error() string {
	return fmt.Sprintf("agent error: code=%s detail=%s retryable=%v", e.Code, e.Detail, e.Retryable)
}

// Unwrap lets errors.Is(err, ErrAgent) succeed for any
// *AgentError.
func (e *AgentError) Unwrap() error { return ErrAgent }

// pendingResponse is the channel a request method waits on
// for its Response. Closed by the reader goroutine on Close.
type pendingResponse struct {
	resp chan *wirev1.Response
}

// Client is the typed-RPC client over framed SSH pipes.
type Client struct {
	stdin  io.WriteCloser
	stdout io.Reader

	writeMu sync.Mutex // serializes frame writes (C-07)
	nextID  atomic.Uint64

	pendingMu sync.Mutex
	pending   map[uint64]*pendingResponse

	closeOnce sync.Once
	closed    chan struct{}
	readerWG  sync.WaitGroup

	// readerDone is closed when readLoop exits (EOF, read
	// error, or end-of-stream). In-flight sendRequest calls
	// select on this in addition to ctx.Done() so an agent
	// crash mid-Apply fails the call promptly rather than
	// waiting for ctx-timeout (which is often minutes for
	// long-running Applies). Populated with the underlying
	// read error via readerErr (atomic.Pointer) so callers
	// see the actual cause.
	readerDone chan struct{}
	readerErr  atomic.Pointer[error]
}

// Open constructs a Client over caller-supplied pipes and
// starts the background reader goroutine. The pipes typically
// come from `exec.Command("ssh", host, "kensa", "agent",
// "--stdio").StdinPipe()` / `.StdoutPipe()` — the SSH
// subprocess lifecycle is the caller's responsibility.
func Open(stdin io.WriteCloser, stdout io.Reader) (*Client, error) {
	c := &Client{
		stdin:      stdin,
		stdout:     stdout,
		pending:    make(map[uint64]*pendingResponse),
		closed:     make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	c.readerWG.Add(1)
	go c.readLoop()
	return c, nil
}

// Close terminates the client: closes stdin so the agent
// sees EOF and exits, waits up to 1 second for the reader
// goroutine to drain stdout, and rejects in-flight calls with
// ErrClientClosed. Idempotent. Per spec C-04 the wait is
// bounded — a misbehaving peer (agent that doesn't close
// stdout on stdin-EOF) doesn't hang Close forever.
//
// If the bounded wait expires, Close returns nil anyway —
// the reader goroutine is abandoned. The caller's process
// will exit and the goroutine dies with it. Not ideal, but
// preferable to a permanent hang on a misbehaving agent.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		// Closing stdin makes the agent exit; that closes
		// the agent's stdout, which makes our reader's
		// agent.Read return io.EOF and the reader exits.
		_ = c.stdin.Close()
		// Fail in-flight pending callers immediately
		// instead of waiting for the reader to drain.
		c.pendingMu.Lock()
		for id, p := range c.pending {
			close(p.resp)
			delete(c.pending, id)
		}
		c.pendingMu.Unlock()
	})
	// Bounded wait on reader goroutine.
	done := make(chan struct{})
	go func() {
		c.readerWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-timeAfter(closeWaitTimeout):
		// Reader is stuck; abandon it. Goroutine dies when
		// process exits.
	}
	return nil
}

// closeWaitTimeout is the bound on Close's wait for the
// reader goroutine. Exposed as a package var so tests can
// shrink it. 1 second matches spec C-04.
var closeWaitTimeout = 1 * time.Second

// timeAfter is `time.After` indirection so tests don't
// actually wait 1 second on the closeWaitTimeout path.
var timeAfter = time.After

// nextCorrelationID returns a monotonically-increasing u64.
// We start at 1 so 0 stays meaningfully "unset" if it
// appears in a Response.
func (c *Client) nextCorrelationID() uint64 {
	// atomic.Uint64.Add wraps around at MaxUint64; given a
	// realistic call rate (millions per session), the wrap
	// is astronomically far away. No need to detect.
	return c.nextID.Add(1)
}

// readLoop is the background reader. Drains stdout, parses
// frames as Responses, validates, and routes by
// correlation_id. On exit (EOF or any error), closes
// readerDone so pending callers can fail-fast without
// waiting for ctx-timeout.
func (c *Client) readLoop() {
	defer func() {
		// Closing readerDone before readerWG.Done() ensures
		// in-flight sendRequest callers selecting on
		// readerDone observe the close before any caller
		// observing readerWG.Wait()'s release sees the
		// readerDone state.
		close(c.readerDone)
		c.readerWG.Done()
	}()
	for {
		frameType, payload, err := agent.Read(c.stdout, nil)
		if err != nil {
			// EOF or any read error terminates the loop.
			// Stash err so sendRequest can wrap it with
			// ErrAgentStreamClosed for fail-fast.
			c.readerErr.Store(&err)
			return
		}
		if frameType != agent.FramePayload {
			// L-012+ frame types arrive here (heartbeat,
			// control). At L-011 we have no router for
			// them — log via dropping and continue.
			continue
		}
		var resp wirev1.Response
		if err := proto.Unmarshal(payload, &resp); err != nil {
			// Malformed Response — agent shipped bad
			// protobuf. Drop and continue; the in-flight
			// caller for this correlation_id will time out
			// via ctx.
			continue
		}
		if err := wirev1.ValidateResponse(&resp); err != nil {
			// Multi-variant Response — agent dispatcher
			// bug. Drop; in-flight caller times out via
			// ctx.
			continue
		}
		c.routeResponse(&resp)
	}
}

// routeResponse looks up the pending entry by correlation_id
// and delivers the response. If no entry exists, the
// response is for a cancelled or timed-out call — drop it.
func (c *Client) routeResponse(resp *wirev1.Response) {
	c.pendingMu.Lock()
	p, ok := c.pending[resp.GetCorrelationId()]
	if ok {
		delete(c.pending, resp.GetCorrelationId())
	}
	c.pendingMu.Unlock()
	if !ok {
		return
	}
	// pending.resp is size-1 buffered, and we just deleted
	// the entry from the map above so no other goroutine
	// can race to fill the slot. The send always succeeds
	// without blocking; a select-with-default here would be
	// dead code masking a future buffer-size regression.
	p.resp <- resp
}

// sendRequest is the core RPC primitive: assign id, register
// pending, write frame, wait for response or ctx.
func (c *Client) sendRequest(ctx context.Context, payload isRequestPayload) (*wirev1.Response, error) {
	select {
	case <-c.closed:
		return nil, ErrClientClosed
	default:
	}

	id := c.nextCorrelationID()
	req := &wirev1.Request{
		SchemaVersion: 1,
		CorrelationId: id,
	}
	payload.setOn(req)

	pending := &pendingResponse{resp: make(chan *wirev1.Response, 1)}
	c.pendingMu.Lock()
	c.pending[id] = pending
	c.pendingMu.Unlock()

	// Cleanup helper for ctx-cancel / close paths.
	cleanup := func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}

	reqBytes, err := proto.Marshal(req)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("client: marshal Request: %w", err)
	}

	c.writeMu.Lock()
	err = agent.Write(c.stdin, agent.FramePayload, reqBytes, nil)
	c.writeMu.Unlock()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("client: write Request frame: %w", err)
	}

	select {
	case <-ctx.Done():
		cleanup()
		return nil, ctx.Err()
	case <-c.closed:
		cleanup()
		return nil, ErrClientClosed
	case <-c.readerDone:
		cleanup()
		// Wrap the underlying read error so callers see
		// the cause. Typical case: agent crashed mid-call
		// (io.EOF) or pipe broken (io.ErrUnexpectedEOF).
		if errPtr := c.readerErr.Load(); errPtr != nil {
			return nil, fmt.Errorf("%w: %v", ErrAgentStreamClosed, *errPtr)
		}
		return nil, ErrAgentStreamClosed
	case resp, ok := <-pending.resp:
		if !ok {
			return nil, ErrClientClosed
		}
		return resp, nil
	}
}

// isRequestPayload is a sealed-interface helper: each
// typed-method passes a payload-setter implementing this so
// sendRequest stays type-generic over payload variants.
type isRequestPayload interface {
	setOn(*wirev1.Request)
}

type applyPayload struct{ p *wirev1.Request_Apply }

func (a applyPayload) setOn(req *wirev1.Request) { req.Payload = a.p }

type capturePayload struct{ p *wirev1.Request_Capture }

func (c capturePayload) setOn(req *wirev1.Request) { req.Payload = c.p }

type rollbackPayload struct{ p *wirev1.Request_Rollback }

func (r rollbackPayload) setOn(req *wirev1.Request) { req.Payload = r.p }

type heartbeatPayload struct{ p *wirev1.Request_Heartbeat }

func (h heartbeatPayload) setOn(req *wirev1.Request) { req.Payload = h.p }

type handshakePayload struct{ p *wirev1.Request_Handshake }

func (h handshakePayload) setOn(req *wirev1.Request) { req.Payload = h.p }

// ErrIncompatibleProtocol is returned from Handshake when the
// agent's major version differs from this build's, or when
// the agent explicitly rejects the handshake (HandshakeAck.
// Accepted=false). The wrapped detail message includes the
// agent's major/minor + reason for diagnosis.
var ErrIncompatibleProtocol = errors.New("client: incompatible protocol version")

// MinorMismatchLogger is called when Handshake succeeds with
// a minor-version mismatch (same major, different minor).
// Default writes a one-line warning to stderr; tests inject
// a custom function to capture the call. Setting to nil
// silences the warning entirely.
var MinorMismatchLogger = func(clientMajor, clientMinor, agentMajor, agentMinor uint32, agentBuild string) {
	// L-013+ may replace this with a structured logger.
	// For L-012 a one-line stderr message matches the
	// agent loop's diagnostic style.
	fmt.Fprintf(os.Stderr, "kensa client: handshake accepted with minor version skew: client=%d.%d, agent=%d.%d (build=%q)\n",
		clientMajor, clientMinor, agentMajor, agentMinor, agentBuild)
}

// Apply sends an ApplyRequest and returns the StepResult.
// preState may be nil for non-capturable mechanisms.
//
// Translation rules per spec C-05:
//   - envelope Error set → returns *AgentError wrapping
//     ErrAgent (typed payload, if any, is discarded)
//   - variant mismatch → ErrVariantMismatch
//   - happy path → (StepResult, nil)
func (c *Client) Apply(ctx context.Context, mechanism string, params api.Params, preState *api.PreState) (*api.StepResult, error) {
	paramsStruct, err := wirev1.APIParamsToWire(params)
	if err != nil {
		return nil, fmt.Errorf("client: encode params: %w", err)
	}
	var wirePre *wirev1.WirePreState
	if preState != nil {
		wirePre, err = wirev1.APIPreStateToWire(*preState)
		if err != nil {
			return nil, fmt.Errorf("client: encode preState: %w", err)
		}
	}
	resp, err := c.sendRequest(ctx, applyPayload{p: &wirev1.Request_Apply{
		Apply: &wirev1.ApplyRequest{
			Mechanism: mechanism,
			Params:    paramsStruct,
			PreState:  wirePre,
		},
	}})
	if err != nil {
		return nil, err
	}
	if e := resp.GetError(); e != nil {
		return nil, &AgentError{Code: e.GetCode(), Detail: e.GetDetail(), Retryable: e.GetRetryable()}
	}
	applyResp, ok := resp.GetPayload().(*wirev1.Response_ApplyResp)
	if !ok {
		return nil, fmt.Errorf("%w: want ApplyResp, got %T", ErrVariantMismatch, resp.GetPayload())
	}
	sr := wirev1.WireStepResultToAPI(applyResp.ApplyResp.GetStepResult())
	return &sr, nil
}

// Capture sends a CaptureRequest and returns the PreState.
func (c *Client) Capture(ctx context.Context, mechanism string, params api.Params) (*api.PreState, error) {
	paramsStruct, err := wirev1.APIParamsToWire(params)
	if err != nil {
		return nil, fmt.Errorf("client: encode params: %w", err)
	}
	resp, err := c.sendRequest(ctx, capturePayload{p: &wirev1.Request_Capture{
		Capture: &wirev1.CaptureRequest{
			Mechanism: mechanism,
			Params:    paramsStruct,
		},
	}})
	if err != nil {
		return nil, err
	}
	if e := resp.GetError(); e != nil {
		return nil, &AgentError{Code: e.GetCode(), Detail: e.GetDetail(), Retryable: e.GetRetryable()}
	}
	captureResp, ok := resp.GetPayload().(*wirev1.Response_CaptureResp)
	if !ok {
		return nil, fmt.Errorf("%w: want CaptureResp, got %T", ErrVariantMismatch, resp.GetPayload())
	}
	pre, err := wirev1.WirePreStateToAPI(captureResp.CaptureResp.GetPreState())
	if err != nil {
		return nil, fmt.Errorf("client: decode PreState: %w", err)
	}
	return &pre, nil
}

// Rollback sends a RollbackRequest and returns the
// RollbackResult.
func (c *Client) Rollback(ctx context.Context, preState api.PreState) (*api.RollbackResult, error) {
	wirePre, err := wirev1.APIPreStateToWire(preState)
	if err != nil {
		return nil, fmt.Errorf("client: encode preState: %w", err)
	}
	resp, err := c.sendRequest(ctx, rollbackPayload{p: &wirev1.Request_Rollback{
		Rollback: &wirev1.RollbackRequest{
			PreState: wirePre,
		},
	}})
	if err != nil {
		return nil, err
	}
	if e := resp.GetError(); e != nil {
		return nil, &AgentError{Code: e.GetCode(), Detail: e.GetDetail(), Retryable: e.GetRetryable()}
	}
	rollbackResp, ok := resp.GetPayload().(*wirev1.Response_RollbackResp)
	if !ok {
		return nil, fmt.Errorf("%w: want RollbackResp, got %T", ErrVariantMismatch, resp.GetPayload())
	}
	rr, err := wirev1.WireRollbackResultToAPI(rollbackResp.RollbackResp.GetRollbackResult())
	if err != nil {
		return nil, fmt.Errorf("client: decode RollbackResult: %w", err)
	}
	return &rr, nil
}

// Handshake performs the L-012 version-handshake exchange.
// Sends a HandshakeRequest with this build's ProtocolMajor/
// Minor/Build; awaits HandshakeAck.
//
// Returns:
//   - nil                           — versions are exactly compatible
//   - nil + warning to stderr       — same major, different minor
//                                     (acceptable; MinorMismatchLogger
//                                     is called)
//   - ErrIncompatibleProtocol       — major mismatch OR
//                                     HandshakeAck.Accepted == false
//
// Callers SHOULD call Handshake immediately after Open and
// before any other typed method. L-014 will enforce
// handshake-as-first-message on the agent dispatcher side.
func (c *Client) Handshake(ctx context.Context) error {
	resp, err := c.sendRequest(ctx, handshakePayload{p: &wirev1.Request_Handshake{
		Handshake: &wirev1.HandshakeRequest{
			Major: wirev1.ProtocolMajor,
			Minor: wirev1.ProtocolMinor,
			Build: wirev1.ProtocolBuild,
		},
	}})
	if err != nil {
		return err
	}
	if e := resp.GetError(); e != nil {
		return &AgentError{Code: e.GetCode(), Detail: e.GetDetail(), Retryable: e.GetRetryable()}
	}
	ackResp, ok := resp.GetPayload().(*wirev1.Response_HandshakeAck)
	if !ok {
		return fmt.Errorf("%w: want HandshakeAck, got %T", ErrVariantMismatch, resp.GetPayload())
	}
	ack := ackResp.HandshakeAck
	if !ack.GetAccepted() {
		return fmt.Errorf("%w: agent %d.%d (build=%q) rejected: %s",
			ErrIncompatibleProtocol, ack.GetMajor(), ack.GetMinor(), ack.GetBuild(), ack.GetReason())
	}
	// Defense-in-depth: even if the agent says "accepted",
	// check the major ourselves. Mismatch here means the
	// agent's Compatible() disagrees with ours (different
	// build constants) — log loudly.
	if ack.GetMajor() != wirev1.ProtocolMajor {
		return fmt.Errorf("%w: agent accepted but major differs: client=%d, agent=%d",
			ErrIncompatibleProtocol, wirev1.ProtocolMajor, ack.GetMajor())
	}
	if ack.GetMinor() != wirev1.ProtocolMinor && MinorMismatchLogger != nil {
		MinorMismatchLogger(wirev1.ProtocolMajor, wirev1.ProtocolMinor,
			ack.GetMajor(), ack.GetMinor(), ack.GetBuild())
	}
	return nil
}

// Heartbeat sends a HeartbeatRequest and verifies the
// HeartbeatAck.Token matches.
func (c *Client) Heartbeat(ctx context.Context, token uint64) error {
	resp, err := c.sendRequest(ctx, heartbeatPayload{p: &wirev1.Request_Heartbeat{
		Heartbeat: &wirev1.HeartbeatRequest{Token: token},
	}})
	if err != nil {
		return err
	}
	if e := resp.GetError(); e != nil {
		return &AgentError{Code: e.GetCode(), Detail: e.GetDetail(), Retryable: e.GetRetryable()}
	}
	ack, ok := resp.GetPayload().(*wirev1.Response_HeartbeatAck)
	if !ok {
		return fmt.Errorf("%w: want HeartbeatAck, got %T", ErrVariantMismatch, resp.GetPayload())
	}
	if ack.HeartbeatAck.GetToken() != token {
		return fmt.Errorf("client: heartbeat token mismatch: sent %d, ack %d", token, ack.HeartbeatAck.GetToken())
	}
	return nil
}
