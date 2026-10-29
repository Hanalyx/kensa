package deadman

import (
	"errors"
	"testing"
)

// @spec agent-stdio-subcommand
// @ac AC-09
func TestCaptureAdmissionExcludesMutationAndShutdown(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-09")
	a := New()
	_, captureDone, err := a.BeginCapture()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.BeginMutation(); !errors.Is(err, ErrHandlerBusy) {
		t.Fatalf("mutation overlapped Capture: %v", err)
	}
	if !a.Handling() {
		t.Fatal("Capture absent from busy-input observation")
	}
	captureDone(nil)
	captureDone(nil)
	_, mutationDone, err := a.BeginMutation()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.BeginCapture(); !errors.Is(err, ErrHandlerBusy) {
		t.Fatalf("Capture overlapped mutation: %v", err)
	}
	mutationDone()
	a.StartShutdown(nil)
	if _, _, err := a.BeginCapture(); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("post-shutdown Capture admitted: %v", err)
	}
	if err := a.Drain(); err != nil {
		t.Fatal(err)
	}
	if a.Handling() {
		t.Fatal("completed handler token retained")
	}
}
