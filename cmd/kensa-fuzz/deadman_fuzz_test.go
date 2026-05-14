// Deadman-specific live-host fuzz tests for D-006 (Phase 3
// close). These tests exercise the agent-side in-process
// deadman end-to-end against a real Linux host. Unlike the
// generic runFuzz-based tests in fuzz_integration_test.go,
// these talk to the agent's ArmDeadman / CancelDeadman RPC
// directly to test the wakeup paths (timer fire, SSH kill,
// suspend, clock jump, normal cancel).
//
// **Why a separate file.** The existing runFuzz harness
// injects failure at a known transaction phase (capture,
// apply, validate) and asserts on the engine's rollback
// path. The deadman wakeup paths are different — they
// simulate EXTERNAL events (parent death, signal, timer)
// during a transaction that would otherwise succeed.
// Bypassing the engine to call ArmDeadman directly keeps the
// test surface focused on the deadman primitives.
//
// **Why these tests skip by default.** Two of the four
// (Suspend, ClockJump) require host-destructive operations:
// `systemctl suspend` and `date -s`. Even on a dedicated
// test host these can disrupt other tooling. Each test
// requires its own opt-in env var:
//
//	KENSA_FUZZ_HOST=...              (base host config)
//	KENSA_FUZZ_DEADMAN_SUSPEND=1     opt into suspend test
//	KENSA_FUZZ_DEADMAN_CLOCK=1       opt into clock-jump test
//	KENSA_FUZZ_DEADMAN_SSH_KILL=1    opt into SSH-kill test
//	KENSA_FUZZ_DEADMAN_CANCEL=1      opt into normal-cancel test
//
// **Why two-human review of D-005 didn't gate this.** The
// peer review caught code-level defects in D-005 that unit
// tests could verify. These tests exercise the LIVE-HOST
// behavior the design promises (suspend resistance, clock-
// jump immunity, SSH-kill response time). They're the
// final integration gate before Phase 3 is "done."
//
// Spec: docs/roadmap/PHASE-3-BREAKDOWN.md D-006.

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/dispatcher"
	sshtransport "github.com/Hanalyx/kensa/internal/transport/ssh"
)

// witnessFile is the on-host path the rollback command
// touches when the deadman fires. We choose a deterministic
// path so the post-test verification (over a fresh SSH
// connection) can read it back.
const witnessFile = "/tmp/kensa-deadman-fuzz-witness"

// rollbackCommands returns a rollback-script command set
// that writes a witness file. Used by all four tests so
// each can assert "witness exists" → fired, "witness
// missing" → didn't fire.
func rollbackCommands() []string {
	return []string{
		// Each invocation writes a unique timestamped marker
		// so re-runs don't see stale state from a prior run.
		fmt.Sprintf("echo deadman-fired-at=$(date +%%s) > %s", witnessFile),
	}
}

// deadmanHostConfig builds an SSH transport against
// KENSA_FUZZ_HOST. Returns (nil, false) when the env var is
// unset so the caller can t.Skip.
func deadmanHostConfig(t *testing.T) (api.HostConfig, bool) {
	t.Helper()
	host := os.Getenv("KENSA_FUZZ_HOST")
	if host == "" {
		return api.HostConfig{}, false
	}
	return api.HostConfig{
		Hostname:       host,
		Port:           22,
		User:           os.Getenv("KENSA_FUZZ_USER"),
		KeyPath:        os.Getenv("KENSA_FUZZ_KEY"),
		Sudo:           os.Getenv("KENSA_FUZZ_SUDO") == "1",
		StrictHostKeys: false,
	}, true
}

// removeWitness clears the witness file via a one-shot
// SSH command. Called at the start of each test to
// guarantee a clean slate.
func removeWitness(ctx context.Context, t *testing.T, cfg api.HostConfig) {
	t.Helper()
	tr, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("ssh connect for witness cleanup: %v", err)
	}
	defer tr.Close()
	if _, err := tr.Run(ctx, "rm -f "+witnessFile); err != nil {
		t.Fatalf("rm witness: %v", err)
	}
}

// witnessExists checks for the witness file via a fresh SSH
// connection. We open a fresh connection on purpose: the
// agent-channel SSH may have been forcibly terminated by
// the test (SSH-kill test).
func witnessExists(ctx context.Context, t *testing.T, cfg api.HostConfig) bool {
	t.Helper()
	tr, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("ssh connect for witness check: %v", err)
	}
	defer tr.Close()
	res, err := tr.Run(ctx, "test -f "+witnessFile+" && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("witness check: %v", err)
	}
	return strings.TrimSpace(res.Stdout) == "PRESENT"
}

// TestFuzz_DeadmanFiresOnTimer is the baseline live-host
// test: arm a 5s deadman, do nothing, verify rollback fires
// within ~6s. Locks the timer wakeup path end-to-end.
func TestFuzz_DeadmanFiresOnTimer(t *testing.T) {
	cfg, ok := deadmanHostConfig(t)
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}
	if os.Getenv("KENSA_FUZZ_DEADMAN_TIMER") != "1" {
		t.Skip("KENSA_FUZZ_DEADMAN_TIMER not set (opt-in flag)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	removeWitness(ctx, t, cfg)

	tr, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("bootstrap ssh: %v", err)
	}
	defer tr.Close()

	c, cleanup, err := dispatcher.OpenAgent(ctx, tr, cfg.Hostname, dispatcher.Options{User: cfg.User})
	if err != nil {
		t.Fatalf("OpenAgent: %v", err)
	}
	defer cleanup()

	txnID := "fuzz-deadman-timer-" + t.Name()
	firesAt, err := c.ArmDeadman(ctx, txnID, 5, rollbackCommands())
	if err != nil {
		t.Fatalf("ArmDeadman: %v", err)
	}
	if firesAt < time.Now().Unix() {
		t.Errorf("firesAt %d is in the past", firesAt)
	}

	// Wait for fire (5s + slop).
	time.Sleep(7 * time.Second)

	if !witnessExists(ctx, t, cfg) {
		t.Errorf("deadman did not fire: witness file %s missing on host", witnessFile)
	}
}

// TestFuzz_DeadmanCancelStopsRollback locks Q1.c contract:
// CancelDeadman before the window expires must prevent the
// rollback from firing.
func TestFuzz_DeadmanCancelStopsRollback(t *testing.T) {
	cfg, ok := deadmanHostConfig(t)
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}
	if os.Getenv("KENSA_FUZZ_DEADMAN_CANCEL") != "1" {
		t.Skip("KENSA_FUZZ_DEADMAN_CANCEL not set (opt-in flag)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	removeWitness(ctx, t, cfg)

	tr, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("bootstrap ssh: %v", err)
	}
	defer tr.Close()

	c, cleanup, err := dispatcher.OpenAgent(ctx, tr, cfg.Hostname, dispatcher.Options{User: cfg.User})
	if err != nil {
		t.Fatalf("OpenAgent: %v", err)
	}
	defer cleanup()

	txnID := "fuzz-deadman-cancel-" + t.Name()
	if _, err := c.ArmDeadman(ctx, txnID, 5, rollbackCommands()); err != nil {
		t.Fatalf("ArmDeadman: %v", err)
	}
	// Cancel almost immediately.
	time.Sleep(200 * time.Millisecond)
	wasActive, err := c.CancelDeadman(ctx, txnID)
	if err != nil {
		t.Fatalf("CancelDeadman: %v", err)
	}
	if !wasActive {
		t.Errorf("CancelDeadman: wasActive=false, want true")
	}

	// Wait past the window — rollback must NOT fire.
	time.Sleep(7 * time.Second)

	if witnessExists(ctx, t, cfg) {
		t.Errorf("deadman fired despite Cancel: witness file %s exists", witnessFile)
	}
}

// TestFuzz_DeadmanFiresOnSSHKill: forcibly closes the SSH
// transport while a deadman is armed. The agent's pidfd
// (or PR_SET_PDEATHSIG fallback) should fire the rollback
// within ~200ms.
//
// This test exercises the load-bearing parent-death path
// that is the WHOLE POINT of pidfd_open over the
// at(1)/systemd-run scheduler.
func TestFuzz_DeadmanFiresOnSSHKill(t *testing.T) {
	cfg, ok := deadmanHostConfig(t)
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}
	if os.Getenv("KENSA_FUZZ_DEADMAN_SSH_KILL") != "1" {
		t.Skip("KENSA_FUZZ_DEADMAN_SSH_KILL not set (opt-in flag)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	removeWitness(ctx, t, cfg)

	bootstrapTransport, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("bootstrap ssh: %v", err)
	}

	c, cleanup, err := dispatcher.OpenAgent(ctx, bootstrapTransport, cfg.Hostname, dispatcher.Options{User: cfg.User})
	if err != nil {
		_ = bootstrapTransport.Close()
		t.Fatalf("OpenAgent: %v", err)
	}

	txnID := "fuzz-deadman-sshkill-" + t.Name()
	// Long window so the timer doesn't fire on its own
	// before we can kill the SSH session.
	if _, err := c.ArmDeadman(ctx, txnID, 60, rollbackCommands()); err != nil {
		cleanup()
		_ = bootstrapTransport.Close()
		t.Fatalf("ArmDeadman: %v", err)
	}

	// Close the SSH transport abruptly. This severs the
	// agent's parent process (the SSH session); the agent's
	// pidfd (or prctl fallback) should fire the rollback.
	_ = bootstrapTransport.Close()
	// Best-effort cleanup of the client (its underlying
	// pipes are now broken).
	cleanup()

	// Wait for the rollback to fire. Per the design, pidfd
	// detection is sub-200ms, plus rollback-command execution
	// (~100ms for the echo).
	time.Sleep(2 * time.Second)

	if !witnessExists(ctx, t, cfg) {
		t.Errorf("deadman did not fire after SSH kill: witness file %s missing", witnessFile)
	}
}

// TestFuzz_DeadmanFiresAfterSuspend is the CLOCK_BOOTTIME
// property test: suspend the host with a deadman armed,
// resume, verify the deadman fired during the
// suspended-then-resumed-elapsed window.
//
// **Destructive:** systemctl suspend on the test host
// disrupts any other tooling. Opt-in via
// KENSA_FUZZ_DEADMAN_SUSPEND=1 only on a dedicated host.
func TestFuzz_DeadmanFiresAfterSuspend(t *testing.T) {
	cfg, ok := deadmanHostConfig(t)
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}
	if os.Getenv("KENSA_FUZZ_DEADMAN_SUSPEND") != "1" {
		t.Skip("KENSA_FUZZ_DEADMAN_SUSPEND not set (destructive opt-in: systemctl suspend disrupts the host)")
	}

	// Long timeout because the test waits through a suspend
	// + resume cycle. Even a 30s suspend + 10s resume could
	// take a minute on slow VMs.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	removeWitness(ctx, t, cfg)

	tr, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("bootstrap ssh: %v", err)
	}
	defer tr.Close()

	c, cleanup, err := dispatcher.OpenAgent(ctx, tr, cfg.Hostname, dispatcher.Options{User: cfg.User})
	if err != nil {
		t.Fatalf("OpenAgent: %v", err)
	}
	defer cleanup()

	txnID := "fuzz-deadman-suspend-" + t.Name()
	// Arm a 30s deadman. We'll suspend for ~20s; on resume,
	// CLOCK_BOOTTIME should have counted the suspend
	// duration, so the deadman has ~10s left → fires within
	// 10s of resume. Total wait: ~30s from arm.
	if _, err := c.ArmDeadman(ctx, txnID, 30, rollbackCommands()); err != nil {
		t.Fatalf("ArmDeadman: %v", err)
	}

	// Trigger suspend via a side-channel SSH command. The
	// existing tr stays open but the host stops processing
	// it during suspend.
	go func() {
		_, _ = tr.Run(ctx, "sudo systemctl suspend")
	}()

	// Wait long enough for suspend + resume + the deadman
	// to fire post-resume. 60s should be plenty for the
	// 30s-window case.
	time.Sleep(60 * time.Second)

	if !witnessExists(ctx, t, cfg) {
		t.Errorf("deadman did not fire after suspend cycle: witness file %s missing (CLOCK_BOOTTIME suspend-counting failed?)", witnessFile)
	}
}

// TestFuzz_DeadmanDoesNotFireAfterClockJump is the
// CLOCK_BOOTTIME wall-clock-immunity test: jump the host's
// wall clock forward by 1 hour while a 30s deadman is
// armed. The deadman uses CLOCK_BOOTTIME so it should NOT
// fire from the wall-clock jump; only after the actual 30s
// of elapsed-real-time passes.
//
// **Destructive:** date -s on the test host can break
// other tooling (cron, TLS cert validation, systemd
// timers). Opt-in via KENSA_FUZZ_DEADMAN_CLOCK=1 only on
// a dedicated host that gets re-imaged after.
func TestFuzz_DeadmanDoesNotFireAfterClockJump(t *testing.T) {
	cfg, ok := deadmanHostConfig(t)
	if !ok {
		t.Skip("KENSA_FUZZ_HOST not set")
	}
	if os.Getenv("KENSA_FUZZ_DEADMAN_CLOCK") != "1" {
		t.Skip("KENSA_FUZZ_DEADMAN_CLOCK not set (destructive opt-in: date -s disrupts the host)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	removeWitness(ctx, t, cfg)

	tr, err := sshtransport.Factory{}.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("bootstrap ssh: %v", err)
	}
	defer tr.Close()

	c, cleanup, err := dispatcher.OpenAgent(ctx, tr, cfg.Hostname, dispatcher.Options{User: cfg.User})
	if err != nil {
		t.Fatalf("OpenAgent: %v", err)
	}
	defer cleanup()

	txnID := "fuzz-deadman-clock-" + t.Name()
	// Arm a 30s deadman.
	if _, err := c.ArmDeadman(ctx, txnID, 30, rollbackCommands()); err != nil {
		t.Fatalf("ArmDeadman: %v", err)
	}

	// Jump the wall clock forward 1 hour.
	if _, err := tr.Run(ctx, "sudo date -s '+1 hour'"); err != nil {
		t.Fatalf("date -s: %v", err)
	}

	// Wait 5 seconds — well under the 30s deadman window
	// (CLOCK_BOOTTIME counts ELAPSED seconds, not wall
	// clock). The deadman must NOT have fired.
	time.Sleep(5 * time.Second)

	jumped := witnessExists(ctx, t, cfg)

	// Cleanup: restore the clock (best-effort; if this
	// fails the host needs manual intervention).
	_, _ = tr.Run(ctx, "sudo date -s '-1 hour'")
	// Also cancel the still-running deadman so it doesn't
	// fire after our test exits.
	_, _ = c.CancelDeadman(ctx, txnID)

	if jumped {
		t.Errorf("deadman fired after wall-clock jump (CLOCK_BOOTTIME should be wall-clock-immune): witness file %s exists", witnessFile)
	}
}
