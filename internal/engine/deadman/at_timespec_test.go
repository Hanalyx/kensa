package deadman_test

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/engine/deadman"
	"github.com/Hanalyx/kensa/internal/handler"
)

var atMinutesRe = regexp.MustCompile(`\| at now \+ (\d+) minutes`)

// armAndFindCommand runs Arm and returns the issued command matching match,
// driving the real public path rather than reaching into unexported helpers.
func armAndFindCommand(t *testing.T, tp *substringFakeTransport, window time.Duration, match string) string {
	t.Helper()
	a := deadman.New(window, handler.NewRegistry())
	if _, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{}); err != nil {
		t.Fatalf("Arm (window %s): %v", window, err)
	}
	for _, cmd := range tp.Runs {
		if strings.Contains(cmd, match) {
			return cmd
		}
	}
	t.Fatalf("no command containing %q was issued; ran: %v", match, tp.Runs)
	return ""
}

// TestAtSchedulingNeverFiresEarly is the regression for a deadman that could
// not be armed at all, and for the obvious-looking fix that would have made
// it fire too soon.
//
// Two facts about at(1) have to hold together. It has no sub-minute unit, so
// `now + N seconds` is a parse error, and on any host carrying at the arm
// failed and the engine refused to apply. It also truncates its base time to
// the whole minute before adding the offset, measured on RHEL 9: a 2-minute
// spec submitted at :03, :10 and :17 past the minute scheduled 117, 110 and
// 103 seconds out. So `now + N minutes` delivers ((N-1)*60, N*60].
//
// ceil(window/60) therefore reads as rounding up and behaves as rounding
// down: a 120-second window would become 2 minutes and deliver 61 to 120
// seconds. A deadman that fires early reverts a transaction still
// legitimately in flight, which is worse than one that fires late.
//
// The assertion is on the delivered LOWER BOUND rather than a literal command
// string, because the lower bound is the safety property and the string is
// only today's encoding of it.
//
// @spec deadman-timer
// @ac AC-12
func TestAtSchedulingNeverFiresEarly(t *testing.T) {
	t.Run("deadman-timer/AC-12", func(t *testing.T) {})

	for _, window := range []time.Duration{
		1 * time.Second,
		59 * time.Second,
		60 * time.Second,
		61 * time.Second,
		120 * time.Second, // the default
		121 * time.Second,
		5 * time.Minute,
		1 * time.Hour,
	} {
		t.Run(window.String(), func(t *testing.T) {
			cmd := armAndFindCommand(t, atHostTP(), window, "| at now +")

			if strings.Contains(cmd, "second") {
				t.Fatalf("at command uses a unit at(1) cannot parse: %q", cmd)
			}
			m := atMinutesRe.FindStringSubmatch(cmd)
			if m == nil {
				t.Fatalf("at command has no `now + N minutes` spec: %q", cmd)
			}
			minutes, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("unparseable minute count in %q: %v", cmd, err)
			}

			// at truncates to the minute boundary, so the soonest this can
			// fire is (N-1) whole minutes from now.
			earliest := time.Duration(minutes-1) * time.Minute
			if earliest < window {
				t.Errorf("window %s emitted `now + %d minutes`, which can fire after only %s. "+
					"at(1) truncates its base to the minute, so N minutes delivers ((N-1)*60, N*60]; "+
					"firing early reverts a transaction still in flight",
					window, minutes, earliest)
			}
		})
	}
}

// TestAtSchedulingUsesWholeMinutes anchors the encoding for a reader, so the
// property test above is not the only description of what gets emitted.
//
// @spec deadman-timer
// @ac AC-12
func TestAtSchedulingUsesWholeMinutes(t *testing.T) {
	t.Run("deadman-timer/AC-12", func(t *testing.T) {})

	cmd := armAndFindCommand(t, atHostTP(), 120*time.Second, "| at now +")
	if !strings.Contains(cmd, "at now + 3 minutes") {
		t.Errorf("at command = %q, want `at now + 3 minutes` for the 120s default "+
			"(2 minutes would deliver as little as 61s)", cmd)
	}
}

// TestAtArmRefusedWhenAtdIsNotRunning is the guard for a queued job that
// nothing will run.
//
// at(1) writes to a spool; atd(8) executes it. They are separate, and with atd
// stopped at exits ZERO, prints a normal "job N at <time>" line, queues the
// job, and warns on the same stream. atq then lists it, because atq reads the
// spool as well. Every signal the caller checks says armed.
//
// This matters because the arm is what the engine treats as permission to
// apply. Reporting success here mutates a host behind a timer that can never
// fire, and it is reachable on an ordinary machine: the RHEL `at` package
// enables atd without starting it, so a freshly installed host is in exactly
// this state until reboot. Reproduced on RHEL 9.7 (192.168.1.213).
//
// @spec deadman-timer
// @ac AC-13
func TestAtArmRefusedWhenAtdIsNotRunning(t *testing.T) {
	t.Run("deadman-timer/AC-13", func(t *testing.T) {})

	tp := atHostTP()
	tp.AtdStopped = true

	a := deadman.New(120*time.Second, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err == nil {
		t.Fatal("Arm reported success on a host where atd is not running; " +
			"the engine would apply behind a timer that cannot fire")
	}
	if !strings.Contains(err.Error(), "will not run") {
		t.Errorf("error does not explain why the arm was refused: %v", err)
	}

	// The job is in the spool. Left there, it would fire a rollback for a
	// transaction that was never armed if atd is started later.
	var removed bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "atrm") {
			removed = true
		}
	}
	if !removed {
		t.Error("refused the arm but left the job queued; starting atd later would fire it")
	}
}

// TestAtArmRefusedWhenAtExitsNonZero: the previous code never looked at the
// exit status at all, taking a parsed job ID as proof of scheduling.
//
// @spec deadman-timer
// @ac AC-13
func TestAtArmRefusedWhenAtExitsNonZero(t *testing.T) {
	t.Run("deadman-timer/AC-13", func(t *testing.T) {})

	tp := atHostTP()
	tp.Hook = func(cmd string) (*api.CommandResult, bool) {
		if strings.Contains(cmd, "| at now +") {
			return &api.CommandResult{
				ExitCode: 1,
				Stdout:   "job 42 at Thu Apr 15 12:00:00 2026",
				Stderr:   "at: cannot write to spool",
			}, true
		}
		return nil, false
	}

	a := deadman.New(120*time.Second, handler.NewRegistry())
	if _, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{}); err == nil {
		t.Fatal("Arm succeeded although at(1) exited non-zero")
	}
}

// TestBothSchedulersAreArmedWhenBothPresent locks the two-net design.
//
// The schedulers cover different failures and neither covers both. systemd-run
// is the timer that fires: its executor is PID 1, so there is no state where
// the job is accepted and nothing runs it, which at(1) has whenever atd is
// down. at(1) is the backstop across a REBOOT: a systemd-run transient unit
// lives in tmpfs and a power cycle erases it, while at's spool is on disk and
// atd runs overdue jobs at start. The exposed case is the deadman's own reason
// for existing -- the operator power-cycles a host they can no longer reach,
// and the reboot does not undo an on-disk change.
//
// Arming only the "better" scheduler silently drops one of those guarantees.
//
// @spec deadman-timer
// @ac AC-14
func TestBothSchedulersAreArmedWhenBothPresent(t *testing.T) {
	t.Run("deadman-timer/AC-14", func(t *testing.T) {})

	tp := bothSchedulersTP()
	cmd := armAndFindCommand(t, tp, 120*time.Second, "systemd-run --unit=")
	if !strings.Contains(cmd, "--on-active=120") {
		t.Errorf("systemd-run command = %q, want the window in seconds", cmd)
	}
	// systemd's default timer accuracy is ONE MINUTE, so an unpinned
	// --on-active=120 can fire at 180s. Measured on RHEL 9.6 and Ubuntu 22.04.
	if !strings.Contains(cmd, "--timer-property=AccuracySec=1s") {
		t.Errorf("systemd-run command = %q, want AccuracySec pinned; systemd's "+
			"default AccuracyUSec=1min lets the deadman fire up to a minute late", cmd)
	}

	var armedAt bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "| at now +") {
			armedAt = true
		}
	}
	if !armedAt {
		t.Error("only systemd-run was armed; a reboot erases a transient timer, " +
			"so the at(1) backstop is what survives the power cycle the operator " +
			"reaches for when the control channel is gone")
	}
}

// TestFallsThroughToAtWhenSystemdRunRefuses covers presence without
// usability, in the direction the preference flip creates.
//
// systemd-run needs privilege it cannot always get and answers "Interactive
// authentication required" without it, while at(1) on the same host schedules
// fine. A scheduler that is installed but refuses must not end the arm while a
// working one sits beside it.
//
// @spec deadman-timer
// @ac AC-14
func TestFallsThroughToAtWhenSystemdRunRefuses(t *testing.T) {
	t.Run("deadman-timer/AC-14", func(t *testing.T) {})

	tp := bothSchedulersTP()
	tp.SystemdRunRefuses = "Failed to start transient timer unit: Interactive authentication required."

	cmd := armAndFindCommand(t, tp, 120*time.Second, "| at now +")
	if !strings.Contains(cmd, "at now + 3 minutes") {
		t.Errorf("fell through to at(1) but emitted %q", cmd)
	}

	// A non-zero exit does not tell us whether a unit was created — polkit
	// refuses before creating one, but other failures do not. The caller
	// cannot distinguish them and moves on to at(1), so the unit is stopped
	// blind rather than left to fire against a committed transaction.
	var stopped bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "systemctl stop") {
			stopped = true
		}
	}
	if !stopped {
		t.Error("systemd-run exited non-zero and nothing stopped the unit it may have created")
	}
}

// TestFallsThroughToSystemdRunWhenAtdIsDead is the case that motivated the
// flip, in the other direction: at(1) is present and its daemon is not, and
// the host has a working systemd-run.
//
// Before the fall-through this was a terminal refusal, so a host with a
// perfectly good scheduler aborted the transaction. Refusing to arm is right
// only when there is nothing else to try.
//
// @spec deadman-timer
// @ac AC-14
func TestFallsThroughToSystemdRunWhenAtdIsDead(t *testing.T) {
	t.Run("deadman-timer/AC-14", func(t *testing.T) {})

	tp := bothSchedulersTP()
	tp.AtdStopped = true

	// systemd-run is tried first and succeeds, so at is never reached. Force
	// the ordering question by making systemd-run refuse as well, and confirm
	// the arm then fails rather than accepting the dead at.
	tp.SystemdRunRefuses = "Failed to start transient timer unit: Interactive authentication required."
	a := deadman.New(120*time.Second, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err == nil {
		t.Fatal("Arm succeeded with systemd-run refusing and atd dead")
	}
	for _, want := range []string{"systemd-run", "at"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not report the %s attempt: %v", want, err)
		}
	}
}

// TestFailedSystemdRunScheduleLeavesNoTimer: systemd-run exits 0 once the unit
// is queued, so a failed verification can orphan a live timer. The caller then
// advances to at(1) and records only the winner, leaving nothing able to
// cancel it. Sibling of the atrm cleanup on the at path; the class sweep is
// part of the fix.
//
// @spec deadman-timer
// @ac AC-14
func TestFailedSystemdRunScheduleLeavesNoTimer(t *testing.T) {
	t.Run("deadman-timer/AC-14", func(t *testing.T) {})

	tp := bothSchedulersTP()
	tp.Results["LoadState"] = api.CommandResult{Stdout: "not-found"} // verification fails

	if _, _, err := a2(t).Arm(context.Background(), tp, uuid.New(), []api.PreState{}); err != nil {
		t.Fatalf("Arm should have fallen through to at: %v", err)
	}
	var scheduled, stopped bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "systemd-run --unit=") {
			scheduled = true
		}
		if strings.Contains(ran, "systemctl stop") {
			stopped = true
		}
	}
	if !scheduled {
		t.Fatal("systemd-run was never attempted; the test does not cover the orphan case")
	}
	if !stopped {
		t.Error("a systemd-run schedule failed after creating a unit and nothing stopped it")
	}
}

func a2(t *testing.T) *deadman.Armer {
	t.Helper()
	return deadman.New(120*time.Second, handler.NewRegistry())
}

// TestCancelRemovesEveryArmedTimer is the obligation arming two schedulers
// creates. Cancel runs on the COMMIT path, so a timer left behind fires a full
// rollback against a transaction that already succeeded — unprompted, with no
// operator watching and no store record to explain it.
//
// @spec deadman-timer
// @ac AC-15
func TestCancelRemovesEveryArmedTimer(t *testing.T) {
	t.Run("deadman-timer/AC-15", func(t *testing.T) {})

	tp := bothSchedulersTP()
	a := deadman.New(120*time.Second, handler.NewRegistry())
	txn := uuid.New()
	if _, _, err := a.Arm(context.Background(), tp, txn, []api.PreState{}); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if err := a.Cancel(context.Background(), tp, txn); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	var atrm, stopped bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "atrm") {
			atrm = true
		}
		if strings.Contains(ran, "systemctl stop") {
			stopped = true
		}
	}
	if !atrm {
		t.Error("the at(1) job was never removed; it fires after commit and rolls back a committed transaction")
	}
	if !stopped {
		t.Error("the systemd-run timer was never stopped; it fires after commit")
	}
}

// TestPartialCancelFailsTheCancel: with two timers armed, one cancel can fail
// while the other succeeds. Reporting success there is the worst outcome in
// this package — the engine records COMMITTED and a live timer contradicts it
// minutes later. The engine treats a Cancel error as "the deadman will fire"
// and rolls back in-band, which is the honest verdict.
//
// @spec deadman-timer
// @ac AC-15
func TestPartialCancelFailsTheCancel(t *testing.T) {
	t.Run("deadman-timer/AC-15", func(t *testing.T) {})

	tp := bothSchedulersTP()
	a := deadman.New(120*time.Second, handler.NewRegistry())
	txn := uuid.New()
	if _, _, err := a.Arm(context.Background(), tp, txn, []api.PreState{}); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// atrm fails; the systemd-run cancel still succeeds.
	tp.Hook = func(cmd string) (*api.CommandResult, bool) {
		if strings.HasPrefix(cmd, "atrm") {
			return &api.CommandResult{ExitCode: 1, Stderr: "atrm: cannot remove job"}, true
		}
		return nil, false
	}

	err := a.Cancel(context.Background(), tp, txn)
	if err == nil {
		t.Fatal("Cancel reported success with one timer still armed; the engine " +
			"would record COMMITTED and the survivor would roll it back")
	}
	if !strings.Contains(err.Error(), "1 of 2") {
		t.Errorf("error does not say how many timers survived: %v", err)
	}

	// The failure must not short-circuit the other cancel: returning early
	// would guarantee the untracked survivor this test exists to prevent.
	var stopped bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "systemctl stop") {
			stopped = true
		}
	}
	if !stopped {
		t.Error("a failed atrm skipped the systemd-run cancel; every armed timer must be attempted")
	}
}

// TestAtJobVerificationIsAnchored: atq lines are "<id>\t<date>...", and the
// date column is full of digits. A bare substring test for job "4" therefore
// matches a queue containing only job 42 — so the last gate before the engine
// applies would pass on somebody else's timer, or on a job that was never
// really queued. verifyAtJobGone already anchors on the tab and carries a
// comment naming this hazard; its sibling did not.
//
// @spec deadman-timer
// @ac AC-04
func TestAtJobVerificationIsAnchored(t *testing.T) {
	t.Run("deadman-timer/AC-04", func(t *testing.T) {})

	tp := atHostTP()
	inner := tp.Hook
	tp.Hook = func(cmd string) (*api.CommandResult, bool) {
		if strings.Contains(cmd, "| at now +") {
			// at reports job 4; the spool holds only the unrelated job 42.
			return &api.CommandResult{Stdout: "job 4 at Thu Apr 15 12:00:00 2026"}, true
		}
		return inner(cmd)
	}

	a := deadman.New(120*time.Second, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err == nil {
		t.Fatal("Arm succeeded although job 4 is absent from atq; a substring " +
			"match against job 42 passed the last gate before apply")
	}
}

// TestSystemdRunTransportErrorLeavesNoTimer: a transport error does NOT prove
// the command did not run — it may have executed on the host and the reply
// been lost. systemd-run exits 0 once the unit is queued, so the timer can be
// live while the caller believes the attempt failed. The caller then arms the
// next scheduler and records only that one, leaving a timer nothing can
// cancel: it fires a full rollback against a transaction that has since
// committed, with no event and no store record.
//
// @spec deadman-timer
// @ac AC-14
func TestSystemdRunTransportErrorLeavesNoTimer(t *testing.T) {
	t.Run("deadman-timer/AC-14", func(t *testing.T) {})

	tp := bothSchedulersTP()
	tp.SystemdRunTransportErr = "ssh: connection reset by peer"

	// at still arms, so the transaction proceeds — which is exactly why the
	// orphaned systemd-run unit would go unnoticed.
	if _, _, err := deadman.New(120*time.Second, handler.NewRegistry()).
		Arm(context.Background(), tp, uuid.New(), []api.PreState{}); err != nil {
		t.Fatalf("Arm should have fallen through to at: %v", err)
	}
	var stopped bool
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "systemctl stop") {
			stopped = true
		}
	}
	if !stopped {
		t.Error("a lost systemd-run reply left the unit unstopped and untracked; " +
			"it fires a rollback against a committed transaction")
	}
}
