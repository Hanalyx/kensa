package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/internal/agent/ownedexec"
)

func TestOwnedCommandPreservesOrdinaryExitAndOutput(t *testing.T) {
	tr := New(WithSudo(false))
	result, err := tr.Run(ownedexec.Context(context.Background()), "printf 'output\\n'; printf 'diagnostic\\n' >&2; exit 7")
	if err != nil || result == nil || result.ExitCode != 7 || result.Stdout != "output" || result.Stderr != "diagnostic" {
		t.Fatalf("ordinary command contract changed: %#v %v", result, err)
	}
}

func TestOwnedCommandDoesNotHideCancellationAsExitStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := New(WithSudo(false))
	_, err := tr.Run(ownedexec.Context(ctx), "exit 7")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

func TestOwnedRunningCommandRetainsCancellationError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	marker := filepath.Join(t.TempDir(), "started")
	tr := New(WithSudo(false))
	done := make(chan error, 1)
	go func() {
		_, err := tr.Run(ownedexec.Context(ctx), fmt.Sprintf("printf started > %q; exec sleep 30", marker))
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("running cancellation became ordinary exit status: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled command not joined")
	}
}
