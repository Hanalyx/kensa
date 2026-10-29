//go:build linux

package ownedexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func observe(t *testing.T, fn func() bool) {
	t.Helper()
	end := time.After(5 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if fn() {
			return
		}
		select {
		case <-end:
			t.Fatal("owned-process observation timed out")
		case <-tick.C:
		}
	}
}

// The whole ownership test is isolated in its own process so subreaper state
// cannot adopt unrelated children of the Go test runner.
// @spec agent-stdio-subcommand
// @ac AC-11
func TestOwnedEscapedChildBlocksContinuation(t *testing.T) {
	t.Log("// @spec agent-stdio-subcommand")
	t.Log("// @ac AC-11")
	if os.Getenv("KENSA_OWNED_CASE") == "1" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedIsolatedCase$", "-test.v")
	cmd.Env = append(os.Environ(), "KENSA_OWNED_CASE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated ownership control: %v\n%s", err, output)
	}
}

func TestOwnedIsolatedCase(t *testing.T) {
	if os.Getenv("KENSA_OWNED_CASE") != "1" {
		return
	}
	dir := t.TempDir()
	t.Setenv("KENSA_OWNED_DIR", dir)
	t.Setenv("KENSA_OWNED_ROLE", "parent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := Run(ctx, os.Args[0], "-test.run=^TestOwnedProcessHelper$"); done <- err }()
	ready := filepath.Join(dir, "ready")
	observe(t, func() bool { _, e := os.Stat(ready); return e == nil })
	raw, err := os.ReadFile(ready)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Confirm real adoption after the parent command exited. A detached session
	// and completed shell must not turn this still-live writer into quiescence.
	observe(t, func() bool {
		data, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if e != nil {
			return false
		}
		parts := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
		return len(parts) > 1 && parts[1] == strconv.Itoa(os.Getpid())
	})
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned before escaped writer stopped: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("escaped child did not join")
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writer still present after join: %v", err)
	}
	if _, _, err := Run(context.Background(), "sh", "-c", fmt.Sprintf("printf restored > %q", filepath.Join(dir, "state"))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "state"))
	if err != nil || string(data) != "restored" {
		t.Fatalf("late mutation overwrote restoration: %q %v", data, err)
	}
}

func TestOwnedProcessHelper(t *testing.T) {
	dir := os.Getenv("KENSA_OWNED_DIR")
	role := os.Getenv("KENSA_OWNED_ROLE")
	if dir == "" {
		return
	}
	if role == "parent" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessHelper$")
		cmd.Env = append(os.Environ(), "KENSA_OWNED_ROLE=writer")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if role == "writer" {
		if err := os.WriteFile(filepath.Join(dir, "ready"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			os.Exit(3)
		}
		end := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				break
			}
			if time.Now().After(end) {
				os.Exit(4)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := os.WriteFile(filepath.Join(dir, "state"), []byte("late mutation"), 0o600); err != nil {
			os.Exit(5)
		}
		os.Exit(0)
	}
}
