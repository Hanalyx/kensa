package deadman

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/internal/agent/ownedexec"
)

func holdExecutionOwner(t *testing.T) (func(), <-chan error) {
	t.Helper()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	release := filepath.Join(dir, "release")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		_, _, err := ownedexec.Run(ctx, "/bin/sh", "-c", fmt.Sprintf("printf ready > %q; i=0; while [ ! -f %q ]; do i=$((i+1)); [ \"$i\" -lt 500 ] || exit 3; sleep 0.01; done", ready, release))
		done <- err
		close(finished)
	}()
	waitFile(t, ready)
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0600)
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("execution owner fixture did not join")
		}
	})
	return func() {
		if err := os.WriteFile(release, nil, 0600); err != nil {
			t.Error(err)
		}
	}, done
}

// @spec agent-stdio-subcommand
// @ac AC-10
func TestQueuedRecoveryCancelDoesNotClaimExecution(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	release, owner := holdExecutionOwner(t)
	a := New()
	t.Cleanup(func() { _, _ = a.Cancel("queued") })
	queued := make(chan struct{})
	a.commandQueued = func() { close(queued) }
	target := filepath.Join(t.TempDir(), "should-not-launch")
	if _, err := a.ArmDeadman("queued", time.Millisecond, []string{fmt.Sprintf("printf bad > %q", target)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("command did not wait behind held owner")
	}
	a.mu.Lock()
	started := a.active["queued"].started
	a.mu.Unlock()
	if started {
		t.Fatal("queued recovery counted as executed before Start")
	}
	canceled := make(chan error, 1)
	go func() {
		active, err := a.Cancel("queued")
		if !active && err == nil {
			err = fmt.Errorf("queued arm not canceled")
		}
		canceled <- err
	}()
	select {
	case err := <-canceled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued cancellation waited for unrelated execution owner")
	}
	a.StartShutdown(nil)
	if err := joinDrain(t, a); err != nil {
		t.Fatalf("never-started cancellation became aborted recovery: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("canceled queued command launched: %v", err)
	}
	release()
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestQueuedRecoveryKeepsFullExecutionBudget(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	release, owner := holdExecutionOwner(t)
	a := New()
	t.Cleanup(func() { _, _ = a.Cancel("budget") })
	a.commandTimeout = 400 * time.Millisecond
	queued := make(chan struct{})
	a.commandQueued = func() { close(queued) }
	target := filepath.Join(t.TempDir(), "restored")
	if _, err := a.ArmDeadman("budget", time.Millisecond, []string{fmt.Sprintf("sleep 0.02; printf restored > %q", target)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-queued:
	case <-time.After(5 * time.Second):
		t.Fatal("actual queue not observed")
	}
	// Exceed the scaled execution budget while another command owns the slot.
	<-time.After(450 * time.Millisecond)
	a.mu.Lock()
	job := a.active["budget"]
	if job == nil {
		a.mu.Unlock()
		t.Fatal("queue expired before acquiring an execution budget")
	}
	started := job.started
	a.mu.Unlock()
	if started {
		t.Fatal("queue consumed actual-start classification")
	}
	release()
	if err := <-owner; err != nil {
		t.Fatal(err)
	}
	a.StartShutdown(nil)
	if err := joinDrain(t, a); err != nil {
		t.Fatalf("queue consumed command execution budget: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "restored" {
		t.Fatalf("queued command never received its execution budget: %q %v", data, err)
	}
}
