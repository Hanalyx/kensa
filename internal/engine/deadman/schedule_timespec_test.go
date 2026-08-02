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

// armOn runs Arm against tp with the given window and returns the command
// matching match, driving the real public path rather than reaching into
// unexported helpers.
func armOn(t *testing.T, tp *substringFakeTransport, window time.Duration, match string) string {
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

var atMinutesRe = regexp.MustCompile(`\| at now \+ (\d+) minutes`)

// TestAtSchedulingNeverFiresEarly is the regression for the deadman that
// could not arm, and for the arithmetic that first replaced it.
//
// Two facts about at(1) have to hold together. It has no sub-minute unit, so
// `now + N seconds` is a parse error and the deadman could not be armed at
// all on a host carrying at. It also truncates its base time to the whole
// minute before adding the offset, measured on RHEL 9: a 2-minute spec
// submitted at :03, :10 and :17 past the minute scheduled 117, 110 and 103
// seconds out. So `now + N minutes` delivers ((N-1)*60, N*60].
//
// The first fix used ceil(window/60), which reads as rounding up and behaves
// as rounding down: a 120-second window became 2 minutes and delivered 61 to
// 120 seconds. A deadman that fires early reverts a transaction still
// legitimately in flight, which is worse than one that fires late.
//
// The assertion is on the delivered LOWER BOUND rather than on a literal
// command string, because the lower bound is the safety property and the
// string is only today's encoding of it.
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
			cmd := armOn(t, atHostTP(), window, "| at now +")

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

	cmd := armOn(t, atHostTP(), 120*time.Second, "| at now +")
	if !strings.Contains(cmd, "at now + 3 minutes") {
		t.Errorf("at command = %q, want `at now + 3 minutes` for the 120s default "+
			"(2 minutes would deliver as little as 61s)", cmd)
	}
}

// TestSchedulerPrefersSystemdRunWhenBothPresent locks the preference.
// systemd-run takes seconds natively, so it is the only one of the two that
// delivers the window as asked. Every RHEL 8 and RHEL 9 host on the fleet
// carries both.
//
// @spec deadman-timer
// @ac AC-11
func TestSchedulerPrefersSystemdRunWhenBothPresent(t *testing.T) {
	t.Run("deadman-timer/AC-11", func(t *testing.T) {})

	tp := atHostTP()
	tp.Results["__SDR_FOUND__"] = api.CommandResult{Stdout: "__SDR_FOUND__"}
	tp.Results["LoadState"] = api.CommandResult{Stdout: "loaded"}

	cmd := armOn(t, tp, 120*time.Second, "systemd-run --unit=")
	if !strings.Contains(cmd, "--on-active=120") {
		t.Errorf("systemd-run command = %q, want the exact window --on-active=120", cmd)
	}
	for _, ran := range tp.Runs {
		if strings.Contains(ran, "| at now +") {
			t.Errorf("scheduled via at(1) despite systemd-run being available: %q", ran)
		}
	}
}

// TestSchedulerFallsThroughWhenSystemdRunRefuses covers presence without
// usability.
//
// systemd-run is installed on every fleet host but needs privilege it cannot
// always get: as an unprivileged user it answers "Failed to start transient
// timer unit: Interactive authentication required" and exits 1, while at(1)
// on the same host schedules fine. Detection that commits to the preferred
// scheduler at probe time makes the working one unreachable in precisely the
// case where it would rescue the arm, and the transaction aborts with a
// usable scheduler sitting idle.
//
// @spec deadman-timer
// @ac AC-11
func TestSchedulerFallsThroughWhenSystemdRunRefuses(t *testing.T) {
	t.Run("deadman-timer/AC-11", func(t *testing.T) {})

	tp := atHostTP() // at present and working
	tp.Results["__SDR_FOUND__"] = api.CommandResult{Stdout: "__SDR_FOUND__"}
	tp.Results["LoadState"] = api.CommandResult{Stdout: "loaded"}
	// Verbatim from an unprivileged run on RHEL 9.
	tp.SystemdRunRefuses = "Failed to start transient timer unit: Interactive authentication required."

	cmd := armOn(t, tp, 120*time.Second, "| at now +")
	if !strings.Contains(cmd, "at now + 3 minutes") {
		t.Errorf("fell through to at(1) but emitted %q", cmd)
	}
}

// TestArmFailsWhenEverySchedulerRefuses: falling through must not become
// silently succeeding, and the error must say what was tried.
//
// @spec deadman-timer
// @ac AC-11
func TestArmFailsWhenEverySchedulerRefuses(t *testing.T) {
	t.Run("deadman-timer/AC-11", func(t *testing.T) {})

	tp := newSubTP()
	tp.Results["__SDR_FOUND__"] = api.CommandResult{Stdout: "__SDR_FOUND__"}
	tp.Results["__AT_FOUND__"] = api.CommandResult{Stdout: "__AT_FOUND__"}
	tp.SystemdRunRefuses = "Failed to start transient timer unit: Interactive authentication required."
	// at accepts the syntax but atq never confirms the job, so verification
	// fails and the at attempt is refused too.
	tp.Hook = realAtParser

	a := deadman.New(120*time.Second, handler.NewRegistry())
	_, _, err := a.Arm(context.Background(), tp, uuid.New(), []api.PreState{})
	if err == nil {
		t.Fatal("Arm succeeded with no usable scheduler")
	}
	for _, want := range []string{"systemd-run", "at"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not report the %s attempt, so an operator cannot tell what was tried: %v", want, err)
		}
	}
}

// TestAtRemainsTheFallback keeps the fallback honest: a host with at and no
// systemd-run must still arm.
//
// @spec deadman-timer
// @ac AC-11
func TestAtRemainsTheFallback(t *testing.T) {
	t.Run("deadman-timer/AC-11", func(t *testing.T) {})

	cmd := armOn(t, atHostTP(), 120*time.Second, "| at now +")
	if !strings.Contains(cmd, "at now + 3 minutes") {
		t.Errorf("fallback at command = %q", cmd)
	}
}
