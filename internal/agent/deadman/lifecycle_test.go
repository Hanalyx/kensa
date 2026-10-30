package deadman

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitFile(t *testing.T, path string) {
	t.Helper()
	end := time.After(5 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-end:
			t.Fatalf("file not observed: %s", path)
		case <-tick.C:
		}
	}
}
func joinDrain(t *testing.T, a *Armer) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- a.Drain() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("owned work did not join")
		return nil
	}
}

// @spec agent-stdio-subcommand
// @ac AC-10
func TestLifecycleReservedInitializationShutdown(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	a := New()
	reserved, release := make(chan struct{}), make(chan struct{})
	a.beforeAllocate = func() { close(reserved); <-release }
	dir := t.TempDir()
	restored := filepath.Join(dir, "state")
	result := make(chan error, 1)
	go func() {
		_, err := a.ArmDeadman("reserved", time.Minute, []string{fmt.Sprintf("printf captured > %q", restored)})
		result <- err
	}()
	<-reserved
	a.StartShutdown(nil)
	if _, err := a.ArmDeadman("late", time.Minute, nil); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("late admission: %v", err)
	}
	if _, err := a.Cancel("reserved"); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("late cancellation: %v", err)
	}
	if a.ActiveCount() != 1 {
		t.Fatal("initializing obligation disappeared")
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := joinDrain(t, a); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(restored)
	if err != nil || string(data) != "captured" {
		t.Fatalf("reserved job lost recovery: %q, %v", data, err)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-09
func TestLifecycleMutationQuiescenceBeforeRecovery(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	a := New()
	dir := t.TempDir()
	target := filepath.Join(dir, "state")
	if err := os.WriteFile(target, []byte("applied"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, finish, err := a.BeginMutation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ArmDeadman("mutation", time.Minute, []string{fmt.Sprintf("printf captured > %q", target)}); err != nil {
		t.Fatal(err)
	}
	a.StartShutdown(nil)
	<-ctx.Done()
	// Wait until the real event loop has claimed recovery; no sleep substitutes
	// for knowing whether that trigger has actually been processed.
	for {
		a.mu.Lock()
		claimed := a.recovering > 0
		changed := a.changed
		a.mu.Unlock()
		if claimed {
			break
		}
		select {
		case <-changed:
		case <-time.After(5 * time.Second):
			t.Fatal("recovery not claimed")
		}
	}
	// A still-admitted handler performs its final write before returning. The
	// recovered state must win after its actual join, never before that write.
	if err := os.WriteFile(target, []byte("last mutation"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(target)
	if string(data) != "last mutation" {
		t.Fatal("recovery raced active mutation")
	}
	finish()
	if err := joinDrain(t, a); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(target)
	if string(data) != "captured" {
		t.Fatalf("late mutation overwrote recovery: %q", data)
	}
	if _, _, err := a.BeginMutation(); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("late mutation admitted: %v", err)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestLifecycleFailureContinuesAfterJoinAndPreservesProtocolError(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	a := New()
	file := filepath.Join(t.TempDir(), "second")
	if _, err := a.ArmDeadman("ordinary", time.Minute, []string{"exit 7", fmt.Sprintf("printf recovered > %q", file)}); err != nil {
		t.Fatal(err)
	}
	protocol := errors.New("original protocol failure")
	a.StartShutdown(protocol)
	err := joinDrain(t, a)
	if !errors.Is(err, protocol) || !strings.Contains(err.Error(), "command 0") {
		t.Fatalf("lost failure precedence: %v", err)
	}
	data, e := os.ReadFile(file)
	if e != nil || string(data) != "recovered" {
		t.Fatalf("ordinary failure suppressed next command: %q %v", data, e)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-10
func TestLifecycleAcceptedCancellationStopsRemainingSequence(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	a := New()
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	second := filepath.Join(dir, "second")
	first := fmt.Sprintf("printf started > %q; exec sleep 30", started)
	if _, err := a.ArmDeadman("cancel", time.Millisecond, []string{first, fmt.Sprintf("printf unexpected > %q", second)}); err != nil {
		t.Fatal(err)
	}
	waitFile(t, started)
	active, err := a.Cancel("cancel")
	if err != nil || !active {
		t.Fatalf("cancel: %v %v", active, err)
	}
	a.StartShutdown(nil)
	if err := joinDrain(t, a); err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("interrupted recovery was successful: %v", err)
	}
	if _, err := os.Stat(second); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancel continued the remaining sequence")
	}
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestLifecycleCommandTimeoutDoesNotEraseLaterFailureOrRecovery(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	a := New()
	a.commandTimeout = 50 * time.Millisecond
	file := filepath.Join(t.TempDir(), "next")
	if _, err := a.ArmDeadman("timeout", time.Minute, []string{"exec sleep 30", fmt.Sprintf("printf recovered > %q", file)}); err != nil {
		t.Fatal(err)
	}
	a.StartShutdown(nil)
	err := joinDrain(t, a)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout was lost: %v", err)
	}
	if data, e := os.ReadFile(file); e != nil || string(data) != "recovered" {
		t.Fatalf("post-timeout continuation: %q %v", data, e)
	}
}

// @spec agent-stdio-subcommand
// @ac AC-10
func TestLifecycleCancellationWinsInitializationBeforeShutdown(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	a := New()
	reserved, release := make(chan struct{}), make(chan struct{})
	a.beforeAllocate = func() { close(reserved); <-release }
	file := filepath.Join(t.TempDir(), "must-not-execute")
	armDone := make(chan error, 1)
	go func() {
		_, err := a.ArmDeadman("cancel-init", time.Minute, []string{fmt.Sprintf("printf bad > %q", file)})
		armDone <- err
	}()
	<-reserved
	cancelDone := make(chan error, 1)
	go func() {
		active, err := a.Cancel("cancel-init")
		if !active && err == nil {
			err = errors.New("cancellation did not own reservation")
		}
		cancelDone <- err
	}()
	for {
		a.mu.Lock()
		accepted := a.active["cancel-init"].canceled
		changed := a.changed
		a.mu.Unlock()
		if accepted {
			break
		}
		select {
		case <-changed:
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation did not linearize")
		}
	}
	a.StartShutdown(nil)
	close(release)
	if err := <-armDone; err != nil {
		t.Fatal(err)
	}
	if err := <-cancelDone; err != nil {
		t.Fatal(err)
	}
	if err := joinDrain(t, a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("shutdown refired accepted cancellation")
	}
}

// @spec agent-stdio-subcommand
// @ac AC-11
func TestLifecycleTeardownErrorIsStickyAfterRealClose(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	a := New()
	injected := errors.New("controlled teardown result")
	a.afterTeardown = func() error { return injected }
	if _, err := a.ArmDeadman("teardown", time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	a.StartShutdown(nil)
	if err := joinDrain(t, a); !errors.Is(err, injected) {
		t.Fatalf("teardown error erased: %v", err)
	}
	if a.ActiveCount() != 0 {
		t.Fatal("actual teardown did not join")
	}
}

// @spec agent-stdio-subcommand
// @ac AC-10
func TestLifecycleMultipleArmsAndRepeatedShutdownExecuteOnce(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-10")
	a := New()
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if _, err := a.ArmDeadman(fmt.Sprintf("job-%d", i), time.Minute, []string{fmt.Sprintf("printf once >> %q", filepath.Join(dir, fmt.Sprintf("state-%d", i)))}); err != nil {
			t.Fatal(err)
		}
	}
	a.StartShutdown(nil)
	a.StartShutdown(nil)
	if err := joinDrain(t, a); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("state-%d", i)))
		if err != nil || string(data) != "once" {
			t.Fatalf("job fired twice or lost: %q %v", data, err)
		}
	}
}
