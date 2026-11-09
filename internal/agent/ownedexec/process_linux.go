//go:build linux

package ownedexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Adoption prevents an exiting shell/double fork from hiding live descendants.
// This affects only the dedicated agent process; no host service is installed.
func prepare() error {
	probe, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("ownedexec: pidfd ownership unavailable: %w", err)
	}
	if err := unix.Close(probe); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("ownedexec: subreaper: %w", err)
	}
	return nil
}

type process struct {
	pid, fd int
	start   string
}

func identity(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", errors.New("ownedexec: malformed process identity")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return "", errors.New("ownedexec: truncated process identity")
	}
	return fields[19], nil
}

func bind(pid int) (*process, error) {
	start, err := identity(pid)
	if err != nil {
		return nil, err
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	final, err := identity(pid)
	if err != nil || final != start {
		_ = unix.Close(fd)
		return nil, errors.New("ownedexec: process identity changed")
	}
	return &process{pid: pid, fd: fd, start: start}, nil
}

func (p *process) close() { _ = unix.Close(p.fd) }

// Children can be attached to any Go runtime thread, not just the main task.
func children(pid int) ([]int, error) {
	tasks, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
	if err != nil {
		return nil, err
	}
	found := make(map[int]bool)
	for _, task := range tasks {
		data, err := os.ReadFile(task)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, value := range strings.Fields(string(data)) {
			child, err := strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			found[child] = true
		}
	}
	result := make([]int, 0, len(found))
	for pid := range found {
		result = append(result, pid)
	}
	return result, nil
}

func (p *process) stopTree() error {
	var owned []*process
	seen := map[int]bool{p.pid: true}
	var capture func(*process) error
	capture = func(parent *process) error {
		before, err := identity(parent.pid)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || before != parent.start {
			return errors.New("ownedexec: descendant parent identity unavailable")
		}
		ids, err := children(parent.pid)
		if err != nil {
			return err
		}
		for _, pid := range ids {
			if seen[pid] {
				continue
			}
			seen[pid] = true
			child, err := bind(pid)
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
				continue
			}
			if err != nil {
				return err
			}
			// Recheck the original parent after binding; its unreaped identity cannot
			// be replaced by a different process and supply an unrelated child list.
			after, err := identity(parent.pid)
			if err != nil || after != parent.start {
				child.close()
				return errors.New("ownedexec: descendant ownership changed")
			}
			childStat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if err != nil {
				child.close()
				return err
			}
			end := strings.LastIndexByte(string(childStat), ')')
			if end < 0 {
				child.close()
				return errors.New("ownedexec: malformed descendant identity")
			}
			fields := strings.Fields(string(childStat[end+1:]))
			if len(fields) <= 19 || fields[1] != strconv.Itoa(parent.pid) || fields[19] != child.start {
				child.close()
				return errors.New("ownedexec: descendant no longer belongs to parent")
			}
			owned = append(owned, child)
			if err := capture(child); err != nil {
				return err
			}
		}
		return nil
	}
	captureErr := capture(p)
	// Pidfds bind every signal to the captured identity, even if it exits or
	// changes its process group/session between the observation and signal.
	var signalErr error
	for _, child := range append(owned, p) {
		if err := unix.PidfdSendSignal(child.fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			signalErr = errors.Join(signalErr, err)
		}
	}
	for _, child := range owned {
		child.close()
	}
	return errors.Join(captureErr, signalErr)
}

func reapChildren() (bool, error) {
	ids, err := children(os.Getpid())
	if err != nil {
		return true, err
	}
	pending := false
	var result error
	for _, pid := range ids {
		var status unix.WaitStatus
		got, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
		if errors.Is(err, unix.ECHILD) {
			pending = true
			continue
		}
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return true, err
		}
		if got == 0 {
			pending = true
		} else if got > 0 && (!status.Exited() || status.ExitStatus() != 0) {
			result = errors.Join(result, fmt.Errorf("ownedexec: adopted command descendant %d failed: %v", pid, status))
		}
	}
	return pending, result
}
