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
