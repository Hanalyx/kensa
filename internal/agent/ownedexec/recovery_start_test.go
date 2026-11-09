package ownedexec

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryLaunchFailureIsNotStarted(t *testing.T) {
	started := false
	_, _, err := RunRecovery(context.Background(), time.Second, func() { started = true }, nil, filepath.Join(t.TempDir(), "missing-executable"))
	if err == nil || started {
		t.Fatalf("failed launch counted as started: started=%v err=%v", started, err)
	}
	if _, ok := err.(*exec.ExitError); ok {
		t.Fatalf("failed launch became process exit: %v", err)
	}
}
