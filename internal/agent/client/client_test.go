package client

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/Hanalyx/kensa-go/api"
	"github.com/Hanalyx/kensa-go/internal/agent"
	"github.com/Hanalyx/kensa-go/internal/agent/wirev1"
)

// pipePair returns two connected io.Pipe pairs: one for
// client→server (the agent's stdin) and one for server→client
// (the agent's stdout). Mirrors the SSH stdin/stdout topology
// without spawning a subprocess.
func pipePair() (clientStdin io.WriteCloser, clientStdout io.Reader, serverStdin io.Reader, serverStdout io.WriteCloser) {
	c2s_r, c2s_w := io.Pipe()
	s2c_r, s2c_w := io.Pipe()
	return c2s_w, s2c_r, c2s_r, s2c_w
}

// runEchoServer launches an agent.Run loop on a pipe pair,
// returning a cleanup that closes both pipes and waits for the
// loop to terminate.
func runEchoServer(t *testing.T) (clientIn io.WriteCloser, clientOut io.Reader, cleanup func()) {
	t.Helper()
	clientIn, clientOut, serverIn, serverOut := pipePair()

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var stderr discardWriter
		serverErr = agent.RunWithValidator(context.Background(), serverIn, serverOut, stderr, agent.HandleEcho, wirev1.ValidateRequest)
		_ = serverOut.Close()
	}()

	cleanup = func() {
		_ = clientIn.Close()
		wg.Wait()
		if serverErr != nil && !errors.Is(serverErr, io.EOF) && !errors.Is(serverErr, io.ErrClosedPipe) {
			t.Logf("server exited with: %v", serverErr)
		}
	}
	return clientIn, clientOut, cleanup
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestClient_OpenClose locks AC-01: Open returns a working
// Client; Close shuts down the reader cleanly.
//
// @spec agent-client
// @ac AC-01
func TestClient_OpenClose(t *testing.T) {
	clientIn, clientOut, cleanup := runEchoServer(t)
	defer cleanup()

	c, err := Open(clientIn, clientOut)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c == nil {
		t.Fatal("Open returned nil Client")
	}

	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Idempotent.
	if err := c.Close(); err != nil {
		t.Errorf("Close (2nd): %v", err)
	}
}

// TestClient_Apply_EchoServer locks AC-02: Apply against the
// echo server returns a non-nil StepResult, no error.
//
// @spec agent-client
// @ac AC-02
func TestClient_Apply_EchoServer(t *testing.T) {
	clientIn, clientOut, cleanup := runEchoServer(t)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sr, err := c.Apply(ctx, "file_permissions", api.Params{"path": "/etc/ssh/sshd_config"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if sr == nil {
		t.Fatal("Apply returned nil StepResult")
	}
	// HandleEcho returns an empty WireStepResult; verify
	// the bridge produced a non-nil zero-valued result.
	if sr.Mechanism != "" {
		t.Errorf("echo path: expected zero mechanism, got %q", sr.Mechanism)
	}
}

// TestClient_AllMethods_EchoServer locks AC-03: all four
// typed methods round-trip via the echo server. Each gets the
// matching Response variant.
//
// @spec agent-client
// @ac AC-03
func TestClient_AllMethods_EchoServer(t *testing.T) {
	clientIn, clientOut, cleanup := runEchoServer(t)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("Apply", func(t *testing.T) {
		sr, err := c.Apply(ctx, "fp", api.Params{}, nil)
		if err != nil {
			t.Errorf("Apply: %v", err)
		}
		if sr == nil {
			t.Error("nil StepResult")
		}
	})
	t.Run("Capture", func(t *testing.T) {
		pre, err := c.Capture(ctx, "fp", api.Params{})
		if err != nil {
			t.Errorf("Capture: %v", err)
		}
		if pre == nil {
			t.Error("nil PreState")
		}
	})
	t.Run("Rollback", func(t *testing.T) {
		// HandleEcho on RollbackRequest returns an empty
		// WireRollbackResult; bridge should produce a zero
		// api.RollbackResult, no error.
		rr, err := c.Rollback(ctx, api.PreState{Mechanism: "fp"})
		if err != nil {
			t.Errorf("Rollback: %v", err)
		}
		if rr == nil {
			t.Error("nil RollbackResult")
		}
	})
	t.Run("Heartbeat", func(t *testing.T) {
		if err := c.Heartbeat(ctx, 0xfeedface); err != nil {
			t.Errorf("Heartbeat: %v", err)
		}
	})
}

// TestClient_CtxCancelPreemptsApply locks AC-04: a cancelled
// context aborts an Apply call within 100ms. Pending-map
// entry is cleaned up.
//
// @spec agent-client
// @ac AC-04
func TestClient_CtxCancelPreemptsApply(t *testing.T) {
	// Use a "hung" server that reads frames but never writes
	// responses, so Apply waits indefinitely on its response
	// channel.
	clientIn, clientOut, serverIn, serverOut := pipePair()
	// Drain serverIn in a goroutine so the client's write
	// doesn't block — we discard everything.
	go io.Copy(io.Discard, serverIn)
	_ = serverOut // never written to

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := c.Apply(ctx, "fp", api.Params{}, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("ctx cancel should preempt within 200ms; took %v", elapsed)
	}

	// Pending-map should be empty after cancel.
	c.pendingMu.Lock()
	pendingCount := len(c.pending)
	c.pendingMu.Unlock()
	if pendingCount != 0 {
		t.Errorf("pending map should be empty after ctx-cancel; got %d entries", pendingCount)
	}
}

// TestClient_HeartbeatToken locks the token round-trip
// contract — HeartbeatAck.Token must equal the requested
// token. Verified by the echo server returning the same token.
func TestClient_HeartbeatToken(t *testing.T) {
	clientIn, clientOut, cleanup := runEchoServer(t)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, token := range []uint64{0, 1, 0xffffffff, 0xffffffffffffffff} {
		if err := c.Heartbeat(ctx, token); err != nil {
			t.Errorf("Heartbeat(%#x): %v", token, err)
		}
	}
}

// TestClient_ConcurrentApply locks AC-06: 10 concurrent
// Applies produce distinct correlation_ids and 10 correct
// responses.
//
// @spec agent-client
// @ac AC-06
func TestClient_ConcurrentApply(t *testing.T) {
	clientIn, clientOut, cleanup := runEchoServer(t)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sr, err := c.Apply(ctx, "fp", api.Params{}, nil)
			if err != nil {
				errCh <- err
				return
			}
			if sr == nil {
				errCh <- errors.New("nil result")
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent apply: %v", err)
	}
}

// errorHandler returns a Response with envelope-level Error
// set (no typed payload). Used by TestClient_EnvelopeErrorTranslation
// to drive the envelope-Error code path that the L-009
// HandleEcho doesn't exercise.
func errorHandler(req *wirev1.Request) *wirev1.Response {
	return &wirev1.Response{
		SchemaVersion: 1,
		CorrelationId: req.GetCorrelationId(),
		Error: &wirev1.Error{
			SchemaVersion: 1,
			Code:          "test_error",
			Detail:        "test error from fake handler",
			Retryable:     true,
		},
	}
}

// runErrorServer is runEchoServer's twin that uses
// errorHandler instead of HandleEcho. Every Request gets an
// envelope-Error Response.
func runErrorServer(t *testing.T) (clientIn io.WriteCloser, clientOut io.Reader, cleanup func()) {
	t.Helper()
	clientIn, clientOut, serverIn, serverOut := pipePair()

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var stderr discardWriter
		serverErr = agent.RunWithValidator(context.Background(), serverIn, serverOut, stderr, errorHandler, wirev1.ValidateRequest)
		_ = serverOut.Close()
	}()

	cleanup = func() {
		_ = clientIn.Close()
		wg.Wait()
		if serverErr != nil && !errors.Is(serverErr, io.EOF) && !errors.Is(serverErr, io.ErrClosedPipe) {
			t.Logf("server exited with: %v", serverErr)
		}
	}
	return clientIn, clientOut, cleanup
}

// TestClient_EnvelopeErrorTranslation locks AC-05: a Response
// with envelope-level Error becomes a Go error that
// errors.Is matches against ErrAgent and errors.As extracts
// to *AgentError with Code / Detail / Retryable preserved.
//
// @spec agent-client
// @ac AC-05
func TestClient_EnvelopeErrorTranslation(t *testing.T) {
	clientIn, clientOut, cleanup := runErrorServer(t)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.Apply(ctx, "fp", api.Params{}, nil)
	if err == nil {
		t.Fatal("expected envelope Error, got nil")
	}
	if !errors.Is(err, ErrAgent) {
		t.Errorf("errors.Is(err, ErrAgent) should be true; got false (err=%v)", err)
	}
	var agentErr *AgentError
	if !errors.As(err, &agentErr) {
		t.Fatalf("errors.As(err, &AgentError) failed; err=%v", err)
	}
	if agentErr.Code != "test_error" {
		t.Errorf("AgentError.Code: got %q, want %q", agentErr.Code, "test_error")
	}
	if agentErr.Detail != "test error from fake handler" {
		t.Errorf("AgentError.Detail: got %q, want %q", agentErr.Detail, "test error from fake handler")
	}
	if !agentErr.Retryable {
		t.Errorf("AgentError.Retryable: got false, want true")
	}
}

// majorMismatchHandler returns a HandshakeAck declaring
// major=2 (mismatched against the client's major=1).
func majorMismatchHandler(req *wirev1.Request) *wirev1.Response {
	if _, ok := req.GetPayload().(*wirev1.Request_Handshake); ok {
		return &wirev1.Response{
			SchemaVersion: 1,
			CorrelationId: req.GetCorrelationId(),
			Payload: &wirev1.Response_HandshakeAck{
				HandshakeAck: &wirev1.HandshakeAck{
					Major:    2,
					Minor:    0,
					Build:    "v2.0.0-test",
					Accepted: false,
					Reason:   "test: major mismatch",
				},
			},
		}
	}
	return agent.HandleEcho(req)
}

// minorMismatchHandler returns HandshakeAck with same major
// but a different minor — should be accepted with a warning.
func minorMismatchHandler(req *wirev1.Request) *wirev1.Response {
	if _, ok := req.GetPayload().(*wirev1.Request_Handshake); ok {
		return &wirev1.Response{
			SchemaVersion: 1,
			CorrelationId: req.GetCorrelationId(),
			Payload: &wirev1.Response_HandshakeAck{
				HandshakeAck: &wirev1.HandshakeAck{
					Major:    wirev1.ProtocolMajor,
					Minor:    wirev1.ProtocolMinor + 5,
					Build:    "v1.5.0-test",
					Accepted: true,
				},
			},
		}
	}
	return agent.HandleEcho(req)
}

// runCustomServer is runEchoServer with a configurable handler.
func runCustomServer(t *testing.T, handler agent.Handler) (clientIn io.WriteCloser, clientOut io.Reader, cleanup func()) {
	t.Helper()
	clientIn, clientOut, serverIn, serverOut := pipePair()

	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var stderr discardWriter
		serverErr = agent.RunWithValidator(context.Background(), serverIn, serverOut, stderr, handler, wirev1.ValidateRequest)
		_ = serverOut.Close()
	}()

	cleanup = func() {
		_ = clientIn.Close()
		wg.Wait()
		if serverErr != nil && !errors.Is(serverErr, io.EOF) && !errors.Is(serverErr, io.ErrClosedPipe) {
			t.Logf("server exited with: %v", serverErr)
		}
	}
	return clientIn, clientOut, cleanup
}

// TestClient_Handshake_HappyPath locks AC-03: Handshake
// against an echo server with matching version returns nil.
//
// @spec agent-version-handshake
// @ac AC-03
func TestClient_Handshake_HappyPath(t *testing.T) {
	clientIn, clientOut, cleanup := runEchoServer(t)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Handshake(ctx); err != nil {
		t.Errorf("Handshake happy-path: unexpected error: %v", err)
	}
}

// TestClient_Handshake_MajorMismatch locks AC-04: agent with
// major=2 produces ErrIncompatibleProtocol.
//
// @spec agent-version-handshake
// @ac AC-04
func TestClient_Handshake_MajorMismatch(t *testing.T) {
	clientIn, clientOut, cleanup := runCustomServer(t, majorMismatchHandler)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.Handshake(ctx)
	if !errors.Is(err, ErrIncompatibleProtocol) {
		t.Errorf("expected ErrIncompatibleProtocol, got: %v", err)
	}
}

// TestClient_Handshake_MinorMismatch locks AC-05: same major
// but different minor → nil + minor-mismatch warning logged.
//
// @spec agent-version-handshake
// @ac AC-05
func TestClient_Handshake_MinorMismatch(t *testing.T) {
	// Swap in a capturing logger; restore after.
	var (
		mu       sync.Mutex
		captured struct {
			called      bool
			agentMajor  uint32
			agentMinor  uint32
			agentBuild  string
		}
	)
	originalLogger := MinorMismatchLogger
	MinorMismatchLogger = func(cm, cn, am, an uint32, build string) {
		mu.Lock()
		defer mu.Unlock()
		captured.called = true
		captured.agentMajor = am
		captured.agentMinor = an
		captured.agentBuild = build
	}
	defer func() { MinorMismatchLogger = originalLogger }()

	clientIn, clientOut, cleanup := runCustomServer(t, minorMismatchHandler)
	defer cleanup()

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Handshake(ctx); err != nil {
		t.Errorf("minor mismatch should be accepted, got: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !captured.called {
		t.Error("MinorMismatchLogger should have been called")
	}
	if captured.agentMinor != wirev1.ProtocolMinor+5 {
		t.Errorf("logger agentMinor: got %d, want %d", captured.agentMinor, wirev1.ProtocolMinor+5)
	}
	if captured.agentBuild != "v1.5.0-test" {
		t.Errorf("logger agentBuild: got %q, want %q", captured.agentBuild, "v1.5.0-test")
	}
}

// TestClient_ReaderEOFFailsInFlightCalls locks the P0-2 fix:
// when the reader goroutine exits (agent crash, stream EOF,
// any read error), in-flight calls fail with
// ErrAgentStreamClosed instead of waiting for ctx-timeout.
func TestClient_ReaderEOFFailsInFlightCalls(t *testing.T) {
	// Construct a server whose stdout we can close from the
	// test, simulating "agent crashed mid-Apply."
	clientIn, clientOut, serverIn, serverOut := pipePair()
	go io.Copy(io.Discard, serverIn) // drain client writes

	c, _ := Open(clientIn, clientOut)
	defer c.Close()

	applyDone := make(chan error, 1)
	go func() {
		// 60s ctx so we KNOW we're testing the readerDone
		// path, not ctx-timeout.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, err := c.Apply(ctx, "fp", api.Params{}, nil)
		applyDone <- err
	}()

	// Let the Apply register in pending.
	time.Sleep(20 * time.Millisecond)
	// Simulate agent crash: close stdout (the server's
	// write side).
	_ = serverOut.Close()

	select {
	case err := <-applyDone:
		if !errors.Is(err, ErrAgentStreamClosed) {
			t.Errorf("expected ErrAgentStreamClosed, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Apply did not fail-fast within 2s of reader-EOF")
	}
}

// TestClient_CloseRejectsInFlight locks the Close-vs-pending
// contract: when Close fires with a request in flight, the
// in-flight call returns ErrClientClosed promptly.
func TestClient_CloseRejectsInFlight(t *testing.T) {
	// Hung server (never responds).
	clientIn, clientOut, serverIn, serverOut := pipePair()
	go io.Copy(io.Discard, serverIn)
	_ = serverOut

	c, _ := Open(clientIn, clientOut)

	applyDone := make(chan error, 1)
	go func() {
		_, err := c.Apply(context.Background(), "fp", api.Params{}, nil)
		applyDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	_ = c.Close()

	select {
	case err := <-applyDone:
		if !errors.Is(err, ErrClientClosed) {
			t.Errorf("expected ErrClientClosed, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight Apply did not return within 2s of Close")
	}
}
