package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"
)

// runAgent is the C-054 placeholder for `kensa agent` — a
// reserved-name stub that exits 1 with a "planned for v1.1"
// message when invoked with --stdio. The actual implementation
// is Track L Phase 1 (gated on L-007 wire-protocol ratification).
//
// Why a stub ships in v1.0:
//   - OpenWatch and other consumers can write code against the
//     interface today without a breaking-change cycle in v1.1.
//   - `kensa agent --help` discloses the planned wire-protocol
//     shape so integrators have a target.
//   - `kensa agent --stdio` exits 1 (runtime, "feature not
//     ready"), distinct from exit 2 (usage error). CI scripts
//     can pin v1.0 with `kensa agent --stdio || workaround` and
//     get reliable false-branch behavior.
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
	fs.BoolVar(&stdio, "stdio", false, "read framed messages from stdin, write responses to stdout (planned for v1.1)")

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

	// --stdio is set; this is the v1.1-target path. Return a
	// non-UsageError so runCLI maps it to exit 1 (runtime),
	// not exit 2 (usage). Operators scripting against v1.0
	// can distinguish "feature not ready yet" from "you
	// typed bad flags."
	return errors.New(
		"agent mode is planned for v1.1 with the kernel-primitive migration (Track L Phase 1). " +
			"In v1.0, use direct-SSH transport: kensa check / remediate / rollback against the host directly.")
}

// printAgentUsage describes the planned v1.1 wire-protocol
// surface so v1.0 consumers can write integration code today.
// The shape disclosure (stdin / stdout / length-prefixed
// framing) is locked by Track L Phase 1's L-008 through L-012;
// any future change to that shape ratifies through that track,
// not through this stub's help text.
func printAgentUsage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintf(w, `Usage: kensa agent --stdio

[v1.0 PLACEHOLDER — feature lands in v1.1]

The agent subcommand will run kensa as a multi-call binary on
the target host, receiving wire-protocol messages over stdin
and writing responses to stdout. The controller (kensa on the
operator's machine) connects via SSH and drives the agent
through the protocol. This replaces the v1.0 "shell out to
ssh per command" transport with a long-lived agent process,
unlocking the kernel-primitive migration (atomic file ops via
renameat2, deadman timer via timerfd, systemd D-Bus, etc.).

Planned wire-protocol direction:
  stdin   length-prefixed framed messages (controller → agent)
  stdout  length-prefixed framed responses (agent → controller)
  stderr  human-readable diagnostics

The exact wire format ratifies through Track L Phase 1
(deliverables L-007 through L-014; see docs/roadmap/
DELIVERABLES.md). Operators scripting against v1.0 can
expect:

  - The 'agent --stdio' invocation pattern is stable.
  - Length-prefixed framing means consumers buffer one
    message at a time (no streaming-JSON ambiguity).
  - Version handshake on session start; mismatched
    majors abort cleanly.

Today (v1.0):
  --stdio  exits 1 with the "planned for v1.1" message
  --help   shows this disclosure (exit 0)

In v1.1 the agent path replaces direct SSH for handler
invocation. v1.0 consumers should use direct-SSH transport
(kensa check / remediate / rollback against the host
directly) — the operator-facing CLI surface is unchanged
between v1.0 and v1.1; only the underlying transport flips.

Flags:
%s`, fs.FlagUsages())
}
