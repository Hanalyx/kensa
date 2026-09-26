package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/pflag"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/dispatcher"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/store"
	"github.com/Hanalyx/kensa/internal/transport/ssh"
)

// runRecover implements `kensa recover` — compensate transactions interrupted
// before they reached a terminal status, using the durable crash-recovery
// journal. It takes the EXCLUSIVE recover.lock to fence against a live engine
// and other recovery runs, reconnects to the host, and rolls each open
// transaction back from its captured pre-state.
func runRecover(ctx context.Context, dbPath string, args []string) error {
	fs := pflag.NewFlagSet("recover", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.SetOutput(io.Discard)

	var (
		showHelp, sudo, strictHostKeys, quiet bool
		host, user, keyPath, sudoPassword     string
		port                                  int
	)
	fs.BoolVarP(&showHelp, "help", ShortHelp, false, "show this help and exit")
	fs.StringVarP(&host, "host", ShortHost, "", "scope recovery to this host (also the SSH target)")
	fs.StringVarP(&user, "user", ShortUser, "", "SSH user (default: current user)")
	fs.IntVarP(&port, "port", ShortPort, 22, "SSH port")
	fs.StringVar(&keyPath, "key", "", "SSH private key path")
	fs.BoolVar(&sudo, "sudo", false, "wrap commands in sudo")
	fs.StringVar(&sudoPassword, "sudo-password", "", "sudo password for non-NOPASSWD hosts (or KENSA_SUDO_PASSWORD)")
	fs.BoolVar(&strictHostKeys, "strict-host-keys", false, "verify SSH host keys; reject unknown")
	fs.BoolVarP(&quiet, "quiet", ShortQuiet, false, "suppress default output")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			printRecoverUsage(os.Stdout)
			return nil
		}
		return WrapUsageError("try 'kensa recover --help'", err)
	}
	if showHelp {
		printRecoverUsage(os.Stdout)
		return nil
	}
	if host == "" {
		return NewUsageError("kensa recover requires --host: recovery reconnects to the target to compensate the interrupted transaction")
	}

	resolvedSudoPwd, err := resolveSudoPasswordFor(fs, sudoPassword, sudo, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	hostCfg := api.HostConfig{
		Hostname: host, User: user, Port: port, KeyPath: keyPath,
		StrictHostKeys: strictHostKeys, Sudo: sudo, SudoPassword: resolvedSudoPwd,
	}
	if hostCfg.SudoPassword != "" && !sudoRequiresPassword(ctx, hostCfg) {
		hostCfg.SudoPassword = ""
	}

	// Fence FIRST: take the exclusive recover lock before touching the store,
	// so two recoveries cannot race and recovery cannot act under a live engine.
	lock, err := store.AcquireRecoverLock(store.RecoverLockPath(dbPath), true)
	if err != nil {
		if errors.Is(err, store.ErrRecoverLocked) {
			return fmt.Errorf("kensa recover: the store is in use by a live kensa or another recover run; retry when it finishes")
		}
		return err
	}
	defer func() { _ = lock.Release() }()

	s, err := store.OpenSQLite(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Agent mode (default): recovery rolls back kernel-IO handlers, which need
	// the on-host agent — mirror the remediate spawn. KENSA_NO_AGENT=1 opts out.
	engineOpts := []engine.Option{engine.WithStore(s)}
	if os.Getenv("KENSA_NO_AGENT") != "1" {
		// Private ControlMaster; see the remediate path for why the tag matters.
		bootstrap, err := ssh.Factory{SocketTag: "agent"}.Connect(ctx, hostCfg)
		if err != nil {
			return fmt.Errorf("recover: connect for agent bootstrap: %w", err)
		}
		defer func() { _ = bootstrap.Close() }()
		agentClient, cleanup, err := dispatcher.OpenAgent(ctx, bootstrap, host, dispatcher.Options{
			User: user, Sudo: hostCfg.Sudo, SudoPassword: hostCfg.SudoPassword, Stderr: os.Stderr,
		})
		if err != nil {
			return fmt.Errorf("recover: agent mode: %w", err)
		}
		defer cleanup()
		engineOpts = append(engineOpts, engine.WithAgentClient(agentClient))
	}

	transport, err := ssh.Factory{}.Connect(ctx, hostCfg)
	if err != nil {
		return fmt.Errorf("recover: connect: %w", err)
	}
	defer func() { _ = transport.Close() }()

	e := engine.New(engineOpts...)
	report, err := e.RecoverReport(ctx, transport, host)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	return renderRecoverReport(bodyOut(quiet), os.Stderr, report, host)
}

// renderRecoverReport prints what a recovery run did and turns any refusal
// into a non-nil error, so the command exits non-zero. Compensated entries
// go to out (suppressed by --quiet); refusals always go to errOut, because
// an operator has to act on them.
func renderRecoverReport(out, errOut io.Writer, report *engine.RecoveryReport, host string) error {
	if len(report.Results) == 0 && len(report.Refusals) == 0 {
		fmt.Fprintf(out, "kensa recover: no interrupted transactions found for %s\n", host)
		return nil
	}
	for _, r := range report.Results {
		ruleID := ""
		if r.Envelope != nil {
			ruleID = r.Envelope.RuleID
		}
		fmt.Fprintf(out, "  recovered %s  rule=%s  status=%s  host_unchanged=%v\n",
			r.TransactionID, ruleID, r.Status, r.HostUnchanged)
	}
	if len(report.Results) > 0 {
		fmt.Fprintf(out, "kensa recover: compensated %d interrupted transaction(s) on %s\n", len(report.Results), host)
	}
	if len(report.Refusals) == 0 {
		return nil
	}
	for _, rf := range report.Refusals {
		fmt.Fprintf(errOut, "  refused %s  rule=%s  (nothing was restored; the entry stays open)\n",
			rf.TransactionID, rf.RuleID)
		for _, f := range rf.Findings {
			fmt.Fprintf(errOut, "    %s  step=%d  mechanism=%q  %s\n", f.Code, f.StepIndex, f.Mechanism, f.Detail)
		}
	}
	fmt.Fprintln(errOut, "  Before running recovery again for a refused transaction, check whether the host")
	fmt.Fprintln(errOut, "  changed since the interruption: recovery restores the state captured before it,")
	fmt.Fprintln(errOut, "  over any later change to the same settings.")
	return fmt.Errorf("refused %d interrupted transaction(s) whose step identity could not be established on %s",
		len(report.Refusals), host)
}

func printRecoverUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: kensa recover [flags]

Compensate transactions interrupted before they reached a terminal status,
using the durable crash-recovery journal. Each open transaction is rolled back
from its captured pre-state and recorded as recovered, or as rollback_failed
if a restoration does not complete cleanly. Holds an exclusive recover lock so
it never races a live kensa on the same store.

Before restoring anything, recover checks that each transaction's journal and
captured pre-states agree step for step, and that this kensa has a handler for
every mechanism named. A transaction that fails the check is refused whole:
nothing is restored for it, no result is recorded, and its journal entry stays
open. Other transactions are still recovered. The command exits 1 if any
transaction was refused, after listing each one and why.

A refused transaction stays open. Before running recovery for it again,
including with an upgraded kensa, check whether the host changed since the
interruption: recovery restores the state captured before it, over any later
change to the same settings.

  -H, --host string            scope recovery to this host (also the SSH target; required)
  -u, --user string            SSH user (default: current user)
  -P, --port int               SSH port (default 22)
      --key string             SSH private key path
      --sudo                   wrap commands in sudo
      --sudo-password string   sudo password for non-NOPASSWD hosts
      --strict-host-keys       verify SSH host keys; reject unknown
  -q, --quiet                  suppress default output
  -D, --db string              SQLite transaction-log path (default: .kensa/results.db)

Run after a crash, when no live kensa is operating the host.`)
}
