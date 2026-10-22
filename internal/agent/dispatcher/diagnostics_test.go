package dispatcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanalyx/kensa/internal/agent/client"
)

type gatedDiagnostics struct {
	entered chan struct{}
	release chan struct{}
	first   sync.Once
	active  atomic.Int32
	max     atomic.Int32
	buf     bytes.Buffer // Deliberately unsafe: the session owns serialization.
}

func (w *gatedDiagnostics) Write(p []byte) (int, error) {
	n := w.active.Add(1)
	defer w.active.Add(-1)
	for old := w.max.Load(); n > old; old = w.max.Load() {
		if w.max.CompareAndSwap(old, n) {
			break
		}
	}
	w.first.Do(func() { close(w.entered); <-w.release })
	return w.buf.Write(p)
}

func TestOpenAgent_DiagnosticOwnership(t *testing.T) {
	bin := filepath.Join(findRepoRootForTest(t), "bin", "kensa")
	if !fileExists(bin) {
		t.Fatal("build bin/kensa before diagnostic ownership test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	sink := &gatedDiagnostics{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(sink.release) }) }
	defer release()
	command := make(chan *exec.Cmd, 1)
	type opened struct {
		c       *client.Client
		cleanup func()
		err     error
	}
	ready := make(chan opened, 1)
	go func() {
		c, cleanup, err := OpenAgent(ctx, &fakeTransport{home: "/home/test"}, "test-host", Options{
			LocalBinary: bin, Stderr: sink,
			SSHCommandFunc: func(ctx context.Context, _, _, _ string) *exec.Cmd {
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `printf 'child-before\n' >&2; "$1" agent --stdio; printf 'child-after\n' >&2; exit 7`, "diagnostic-test", bin)
				command <- cmd
				return cmd
			},
		})
		ready <- opened{c, cleanup, err}
	}()
	var cmd *exec.Cmd
	select {
	case cmd = <-command:
	case <-ctx.Done():
		t.Fatal("no subprocess")
	}
	select {
	case <-sink.entered:
	case <-ctx.Done():
		t.Fatal("child stderr never reached sink")
	}
	// The real os/exec copying goroutine must hold the same session write lease.
	coordinator, ok := cmd.Stderr.(*diagnosticWriter)
	if !ok {
		t.Error("subprocess stderr bypassed the session writer")
	} else if coordinator.mu.TryLock() {
		coordinator.mu.Unlock()
		t.Error("child write did not hold the session write lease")
	}
	release()
	var result opened
	select {
	case result = <-ready:
	case <-ctx.Done():
		t.Fatal("OpenAgent stuck")
	}
	if result.err != nil {
		t.Fatalf("OpenAgent: %v", result.err)
	}
	result.cleanup() // Joins the subprocess copier before an unsafe buffer snapshot.
	if sink.max.Load() != 1 {
		t.Errorf("concurrent underlying Write calls: %d", sink.max.Load())
	}
	got := sink.buf.String()
	for _, want := range []string{"child-before", "child-after", "kensa: agent mode", "subprocess exited 7"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %q", want, got)
		}
	}
}

func TestOpenAgent_DiagnosticFileSink(t *testing.T) {
	bin := filepath.Join(findRepoRootForTest(t), "bin", "kensa")
	if !fileExists(bin) {
		t.Fatal("build bin/kensa before file sink test")
	}
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var child *exec.Cmd
	_, cleanup, err := OpenAgent(ctx, &fakeTransport{home: "/home/test"}, "file-sink", Options{
		LocalBinary: bin, Stderr: f,
		SSHCommandFunc: func(ctx context.Context, _, _, _ string) *exec.Cmd {
			child = exec.CommandContext(ctx, "/bin/sh", "-c", `printf 'child-file\n' >&2; exec "$1" agent --stdio`, "diagnostic-test", bin)
			return child
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if child.Stderr != f {
		t.Fatal("file sink lost direct subprocess descriptor wiring")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("child-file")) || !bytes.Contains(got, []byte("agent mode")) {
		t.Fatalf("missing file diagnostics: %s", got)
	}
}

func TestOpenAgent_ErrorJoinsDiagnosticWriter(t *testing.T) {
	var sink bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, cleanup, err := OpenAgent(ctx, &fakeTransport{home: "/home/test"}, "bad-peer", Options{
		LocalBinary: "/bin/true", Stderr: &sink,
		SSHCommandFunc: func(ctx context.Context, _, _, _ string) *exec.Cmd {
			return exec.CommandContext(ctx, "/bin/sh", "-c", `printf 'peer-failed\n' >&2; exit 3`)
		},
	})
	if err == nil || cleanup != nil {
		t.Fatalf("expected failed handshake with no cleanup: %v", err)
	}
	if !strings.Contains(sink.String(), "peer-failed") {
		t.Fatalf("stderr not drained before error return: %q", sink.String())
	}
}

type diagnosticErrorWriter struct{ err error }

func (w diagnosticErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDiagnosticWriter_PreservesWriteError(t *testing.T) {
	sentinel := errors.New("sink failed")
	writer := &diagnosticWriter{out: diagnosticErrorWriter{sentinel}}
	if n, err := writer.Write([]byte("diagnostic")); n != 0 || !errors.Is(err, sentinel) {
		t.Fatalf("Write=%d,%v", n, err)
	}
}

// A value larger than the pipe makes the send fail after the real child closes
// stdin. The error return must reap the child and join its stderr copier.
func TestOpenAgent_PasswordWriteFailureJoinsChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var sink bytes.Buffer
	var child *exec.Cmd
	_, cleanup, err := OpenAgent(ctx, &fakeTransport{home: "/home/test"}, "closed-stdin", Options{
		LocalBinary: "/bin/true", Stderr: &sink, SudoPassword: strings.Repeat("x", 2*1024*1024),
		SSHCommandFunc: func(ctx context.Context, _, _, _ string) *exec.Cmd {
			child = exec.CommandContext(ctx, "/bin/sh", "-c", `exec 0<&-; printf 'stdin closed\n' >&2; exec sleep 30`)
			return child
		},
	})
	if child != nil && child.Process != nil {
		defer func() {
			_ = child.Process.Kill()
			_ = child.Wait()
		}()
	}
	if err == nil || !strings.Contains(err.Error(), "write sudo password") || cleanup != nil {
		t.Fatalf("expected password send error: %v", err)
	}
	if child.ProcessState == nil {
		t.Fatal("error returned before joining subprocess and diagnostic copier")
	}
	_ = sink.String() // Safe after the error path joins the copier.
}
