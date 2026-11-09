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

	"golang.org/x/sys/unix"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/internal/agent"
	"github.com/Hanalyx/kensa/internal/agent/deadman"
	"github.com/Hanalyx/kensa/internal/agent/server"
)

// shutdownGracePeriod is how long the agent waits between ctx
// cancellation and idle blocked-read exit. Active recovery is joined first.
// Long enough for the
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

	// Keep protocol EOF semantics in agent.Run. The command owns admitted
	// mutation/recovery lifetimes, including a blocked read during shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	// A closed output must be a returned I/O error, not fatal SIGPIPE before
	// the recovery owner can drain. This changes no wire framing.
	brokenPipe := make(chan os.Signal, 1)
	signal.Notify(brokenPipe, syscall.SIGPIPE)
	defer signal.Stop(brokenPipe)
	armer := deadman.Default()
	finished := make(chan error, 1)
	loopReturned := make(chan struct{})
	// A busy admitted handler cannot read stdin EOF itself. Observe pipe HUP
	// without consuming frames, and only while handler admission is active.
	// Buffered idle frames still retain the normal framing/EOF semantics.
	pipeWatcherDone := make(chan struct{})
	go func() {
		defer close(pipeWatcherDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-loopReturned:
				return
			case <-ticker.C:
			}
			if !armer.Handling() {
				continue
			}
			descriptors := []unix.PollFd{{Fd: int32(os.Stdin.Fd()), Events: unix.POLLIN}}
			_, err := unix.Poll(descriptors, 0)
			if err != nil && !errors.Is(err, unix.EINTR) {
				armer.RecordError(fmt.Errorf("agent stdin observation: %w", err))
				cancel()
				return
			}
			if descriptors[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				if descriptors[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
					armer.RecordError(errors.New("agent stdin became unavailable"))
				}
				cancel()
				return
			}
		}
	}()
	defer func() { cancel(); <-pipeWatcherDone }()
	go func() {
		err := agent.Run(ctx, os.Stdin, os.Stdout, os.Stderr, server.HandlerFor(armer))
		if err != context.Canceled {
			armer.RecordError(err)
		}
		close(loopReturned)
		finished <- err
	}()
	select {
	case <-finished:
		armer.StartShutdown(nil)
		return armer.Drain()
	case <-ctx.Done():
		// This frontier includes initialization and synchronous handlers as well
		// as watcher goroutines. It never cancels a recovery context.
		armer.StartShutdown(nil)
		grace := time.NewTimer(shutdownGracePeriod)
		defer grace.Stop()
		drainErr := armer.Drain()
		select {
		case <-finished:
		case <-grace.C:
			// Only a read-only frame waiter can remain: closed admission prevents
			// it from launching a late request, and Drain joined every obligation.
		}
		return errors.Join(drainErr, armer.Drain())
	}

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
