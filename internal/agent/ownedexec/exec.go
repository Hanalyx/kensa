// Package ownedexec retains the lifetime of commands started by the agent.
// It is an in-process wait boundary, not a separate supervisor. Unknown
// descendants keep the boundary unresolved; they never authorize continuation.
package ownedexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

type contextKey struct{}

// Context marks handler execution that belongs to the agent lifecycle.
func Context(ctx context.Context) context.Context { return context.WithValue(ctx, contextKey{}, true) }

// IsOwned reports whether local commands must participate in lifecycle joins.
func IsOwned(ctx context.Context) bool { return ctx.Value(contextKey{}) == true }

var execution = make(chan struct{}, 1)

func acquire(ctx context.Context, waiting func()) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case execution <- struct{}{}:
	default:
		if waiting != nil {
			waiting()
		}
		select {
		case execution <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		<-execution
		return err
	}
	return nil
}
func release() { <-execution }

var initialize sync.Once
var initializeErr error

// Prepare enables accounting before an operation can admit mutation or recovery.
func Prepare() error {
	initialize.Do(func() { initializeErr = prepare() })
	return initializeErr
}

// Quiesce waits for all agent-owned children, including adopted descendants.
// A returned handler or parent shell is not a quiescence proof.
// Callers must exclude native exec.Cmd waits not owned by this package. The
// agent dispatcher retains Capture until those waits join; direct concurrent
// calls with untracked children are not supported by this process-wide reaper.
func Quiesce() error {
	if err := acquire(context.Background(), nil); err != nil {
		return err
	}
	defer release()
	if err := Prepare(); err != nil {
		return err
	}
	return quiesce()
}

// Run executes one command, and does not return until its owned work settles.
// Commands share this boundary so a timed-out predecessor cannot overlap the
// next command. Cancellation signals only identity-bound known descendants;
// unknown adopted work is joined rather than guessed at or silently abandoned.
func Run(ctx context.Context, name string, args ...string) (string, string, error) {
	return run(ctx, 0, nil, nil, name, args...)
}

// RunRecovery excludes queue/quiescence time from the unchanged execution
// budget. Started runs only after successful Start; Waiting observes a held
// execution slot without owning it. The helper invokes callbacks without holding a lifecycle lock.
func RunRecovery(ctx context.Context, budget time.Duration, started, waiting func(), name string, args ...string) (string, string, error) {
	return run(ctx, budget, started, waiting, name, args...)
}

func run(ctx context.Context, budget time.Duration, started, waiting func(), name string, args ...string) (string, string, error) {
	if err := acquire(ctx, waiting); err != nil {
		return "", "", err
	}
	defer release()
	if err := Prepare(); err != nil {
		return "", "", err
	}
	if err := quiesce(); err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if budget > 0 {
		executionCtx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		ctx = executionCtx
	}
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	if started != nil {
		started()
	}
	root, err := bind(cmd.Process.Pid)
	if err != nil {
		// Start succeeded, so an accounting failure cannot release ownership.
		fmt.Fprintln(os.Stderr, "kensa agent: unresolved command identity; joining owned work")
		waitErr := cmd.Wait()
		return stdout.String(), stderr.String(), errors.Join(err, waitErr, quiesce())
	}
	defer root.close()
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	var waitErr, stopErr error
	select {
	case waitErr = <-finished:
	case <-ctx.Done():
		stopErr = root.stopTree()
		waitErr = <-finished
	}
	joinErr := quiesce()
	if ctx.Err() == nil && stopErr == nil && joinErr == nil {
		// Preserve ordinary command exit status separately from ownership failure.
		return stdout.String(), stderr.String(), waitErr
	}
	return stdout.String(), stderr.String(), errors.Join(waitErr, ctx.Err(), stopErr, joinErr)
}

func quiesce() error {
	warned := false
	var recorded error
	for {
		pending, err := reapChildren()
		if err != nil {
			recorded = errors.Join(recorded, err)
		}
		if err == nil && !pending {
			return recorded
		}
		if !warned {
			fmt.Fprintln(os.Stderr, "kensa agent: UNRESOLVED owned child/wait; retaining lifetime until quiescent")
			warned = true
		}
		time.Sleep(10 * time.Millisecond)
	}
}
