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
		bootstrap, err := ssh.Factory{}.Connect(ctx, hostCfg)
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
	results, err := e.Recover(ctx, transport, host)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}

	out := bodyOut(quiet)
	if len(results) == 0 {
		fmt.Fprintf(out, "kensa recover: no interrupted transactions found for %s\n", host)
		return nil
	}
	for _, r := range results {
		ruleID := ""
		if r.Envelope != nil {
			ruleID = r.Envelope.RuleID
		}
		fmt.Fprintf(out, "  recovered %s  rule=%s  status=%s  host_unchanged=%v\n",
			r.TransactionID, ruleID, r.Status, r.HostUnchanged)
	}
	fmt.Fprintf(out, "kensa recover: compensated %d interrupted transaction(s) on %s\n", len(results), host)
	return nil
}

func printRecoverUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: kensa recover [flags]

Compensate transactions interrupted before they reached a terminal status,
using the durable crash-recovery journal. Each open transaction is rolled back
from its captured pre-state and recorded as recovered. Holds an exclusive
recover lock so it never races a live kensa on the same store.

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
