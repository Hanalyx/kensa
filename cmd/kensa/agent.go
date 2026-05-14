package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/internal/agent"
	"github.com/Hanalyx/kensa/internal/agent/server"
)

// shutdownGracePeriod is how long the agent waits between ctx
// cancellation and forced os.Exit(0). Long enough for the
// between-frames ctx check to fire naturally if the loop wasn't
// blocked; short enough that operators sending SIGTERM see the
// process exit promptly. Standard production pattern.
const shutdownGracePeriod = 500 * time.Millisecond

// runAgent dispatches `kensa agent`. At L-008 the --stdio mode
// flips from the v1.0 exit-1 placeholder (C-054, shipped
// 2026-05-10) to a live echo loop: read framed wirev1.Request
// messages from stdin, mirror them as Response, write back. The
// echo behavior validates the framing + protobuf roundtrip
// independently of the handler-invocation schema (which lands at
// L-009).
//
// `kensa agent` (no flags) still exits 2 with a usage error
// pointing at --stdio or --help (cli-agent-placeholder C-01,
// preserved). `kensa agent --help` still discloses the planned
// wire-protocol direction (cli-agent-placeholder C-03,
// preserved).
func runAgent(args []string) error {
	args = rewriteLegacyLongForm(args, map[string]bool{
		"stdio": true,
	})

	fs := pflag.NewFlagSet("agent", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp bool
		stdio    bool
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.BoolVar(&stdio, "stdio", false, "read framed Requests from stdin, return typed Responses on stdout (L-009 typed echo; L-011 swaps in real Engine dispatcher)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printAgentUsage(os.Stdout, fs)
			return nil
		}
		return WrapUsageError("try 'kensa agent --help'", err)
	}
	if showHelp {
		printAgentUsage(os.Stdout, fs)
		return nil
	}
	if !stdio {
		return NewUsageError("specify a mode: --stdio (other modes will land with the v1.1 agent surface)")
	}

	// L-008 echo loop. SIGTERM / SIGINT cancel the context.
	//
	// Shutdown protocol:
	//   - agent.Run checks ctx between frames, so a cancellation
	//     that arrives BETWEEN reads preempts cleanly (returns
	//     ctx.Err(), which we intercept to exit 0).
	//   - A cancellation that arrives while io.ReadFull is
	//     blocked on stdin needs a forced exit. Go's runtime
	//     poller does NOT reliably wake a blocked Read on a
	//     pipe fd when another goroutine calls Close(); the
	//     stdin-close trick is not portable across kernel +
	//     Go-version combinations. We use a grace-period
	//     timer instead: 500ms after ctx fires, os.Exit(0).
	//     This is the standard production pattern for "agent
	//     receives SIGTERM but is blocked on I/O."
	//   - L-012's explicit shutdown-message type makes this
	//     side-channel dependency obsolete by giving the
	//     controller a way to tell the agent to drain cleanly.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go func() {
		<-ctx.Done()
		// Grace period for the loop's between-frames ctx
		// check to fire naturally. If the loop is in a Read
		// at the moment of cancellation, the forced exit
		// below terminates the process within bounded time.
		time.Sleep(shutdownGracePeriod)
		os.Exit(0)
	}()

	// L-014 flip: dispatch via server.Handle (real handler
	// router) instead of HandleEcho (test-fixture echo).
	// kensa agent --stdio in production routes Apply /
	// Capture / Rollback to handler.Default() via a fresh
	// LocalTransport per call. HandleEcho stays in the
	// internal/agent package as the test fixture.
	if err := agent.Run(ctx, os.Stdin, os.Stdout, os.Stderr, server.Handle); err != nil {
		// ctx.Err() (cancellation via signal) is a clean
		// shutdown, not a failure — operator-facing exit 0.
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}

// printAgentUsage describes the agent's wire-protocol surface.
// L-008 ships an echo loop (read frame → mirror payload → write
// frame) that L-009+ replaces with the real handler dispatcher.
// The framing format (4-byte big-endian length prefix) is a STUB
// per L-008; L-010 supersedes with the production contract.
func printAgentUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa agent --stdio

Run kensa as a multi-call binary on the target host. The
controller (kensa on the operator's machine) connects via SSH
and drives the agent through a framed wire protocol on stdin/
stdout. This is the target-local execution surface that unlocks
the kernel-primitive migration (atomic file ops via renameat2,
deadman timer via timerfd, systemd D-Bus, etc.).

Wire direction:
  stdin   length-prefixed framed messages (controller → agent)
  stdout  length-prefixed framed responses (agent → controller)
  stderr  human-readable diagnostics

Framing v2 (Track L Phase 1, L-010 production contract):
  Each message is length-prefixed and typed. Wire layout:
    1-byte type discriminator (0x01 PAYLOAD; 0x02-0xFF
      reserved for L-012+ heartbeat / control / binary-push
      channels)
    4-byte big-endian unsigned length prefix
    N bytes of protobuf-encoded payload (wirev1.Request /
      wirev1.Response from internal/agent/wirev1)
  Default max frame size: 16 MiB (controller-negotiable).

Today's behavior (L-009 typed echo):
  --stdio  reads a frame, dispatches on the Request's typed
           payload variant (Apply/Capture/Rollback/Heartbeat),
           returns a matching Response variant with the same
           correlation_id, exits 0 on clean stdin close.
           Validates framing + protobuf + oneof variant
           end-to-end.
  --help   exits 0 with this disclosure.

L-011 replaces HandleEcho with the real handler dispatcher
(routes ApplyRequest → file_permissions.Apply etc., backed by
a local-syscall Transport on the target host).

Flags:
%s`, fs.FlagUsages())
}
