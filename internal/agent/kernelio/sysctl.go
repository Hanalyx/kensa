// Package kernelio holds the agent-side direct-kernel-IO primitives the
// runtime-mechanism handlers use when running on the target host, in
// place of shelling out to sysctl(8) / mount(8) / modprobe(8). Each
// primitive has a matching capability interface that the agent's local
// transport implements; a handler type-asserts the transport (exactly
// as it does for fsatomic.Transport and systemd.Transport) and falls
// back to shell-out when the assertion fails.
//
// This file covers sysctl: runtime parameter reads/writes go directly to
// /proc/sys, the procfs interface the kernel exposes for every sysctl
// key. (Persistence — the /etc/sysctl.d drop-in — is an ordinary file
// write handled via fsatomic, not here.)
package kernelio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidSysctlKey is returned when a key does not map to a path
// safely under /proc/sys (empty, or an attempt to escape the subtree).
var ErrInvalidSysctlKey = errors.New("kernelio: invalid sysctl key")

// procSysRoot is the procfs sysctl root. A var (not const) so tests can
// point it at a temp dir without a real /proc.
var procSysRoot = "/proc/sys"

// SysctlPath maps a sysctl key to its /proc/sys path. The kernel's
// convention is that dots in the key are path separators
// (net.ipv4.ip_forward → /proc/sys/net/ipv4/ip_forward). The result is
// validated to stay within procSysRoot so a crafted key (containing
// "../" or a leading slash) cannot redirect a write outside /proc/sys.
//
// Known limitation: a sysctl key whose component legitimately contains a
// dot (e.g. an interface named "eth0.100" in net.ipv4.conf.<iface>.*)
// is not representable by the dot-as-separator rule and is rejected by
// the caller's read-back mismatch rather than mis-targeted — the
// hardening corpus does not use such keys.
func SysctlPath(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidSysctlKey)
	}
	if strings.ContainsAny(key, "/\x00") {
		return "", fmt.Errorf("%w: %q contains a separator or NUL", ErrInvalidSysctlKey, key)
	}
	rel := strings.ReplaceAll(key, ".", "/")
	p := filepath.Clean(filepath.Join(procSysRoot, rel))
	// The result MUST be a strict descendant of procSysRoot. Rejecting
	// p == procSysRoot also catches keys that collapse to the root (e.g.
	// ".." → "//" → /proc/sys), which carry no real parameter component.
	if p == procSysRoot || !strings.HasPrefix(p, procSysRoot+"/") {
		return "", fmt.Errorf("%w: %q escapes %s", ErrInvalidSysctlKey, key, procSysRoot)
	}
	return p, nil
}

// WriteSysctl sets a kernel parameter at runtime by writing value to its
// /proc/sys file. The kernel applies the value on write; a rejected
// value surfaces as the write error (e.g. EINVAL). A trailing newline is
// appended, matching what sysctl(8) writes. The procfs file already
// exists for every valid key, so this is an open-for-write + write, not
// a create.
func WriteSysctl(key, value string) error {
	p, err := SysctlPath(key)
	if err != nil {
		return err
	}
	// 0 perm: the file exists in procfs, so the mode arg is ignored;
	// O_WRONLY (no O_CREATE) means a nonexistent key fails loudly rather
	// than creating a stray file.
	f, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("kernelio: open %s for write: %w", p, err)
	}
	defer f.Close()
	if _, err := f.WriteString(value + "\n"); err != nil {
		return fmt.Errorf("kernelio: write %q to %s: %w", value, p, err)
	}
	return nil
}

// ReadFileIfExists reads path, returning (content, true, nil) when it
// exists, ("", false, nil) when it does not, and an error for any other
// failure. The sysctl handler uses it to capture the persistence drop-in
// — distinguishing "file absent" (rollback removes it) from "file empty"
// (rollback rewrites it empty) — over the agent's direct-IO path,
// matching the shell path's absent-vs-empty test.
func ReadFileIfExists(path string) (content string, existed bool, err error) {
	b, rerr := os.ReadFile(path)
	if errors.Is(rerr, os.ErrNotExist) {
		return "", false, nil
	}
	if rerr != nil {
		return "", false, fmt.Errorf("kernelio: read %s: %w", path, rerr)
	}
	return string(b), true, nil
}

// MkdirAll creates a directory and any missing parents, like
// os.MkdirAll. Used by handlers (e.g. dconf_set) that must ensure a
// config drop-in directory exists before an atomic write into it, on the
// agent's direct-IO path.
func MkdirAll(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("kernelio: mkdir %s: %w", path, err)
	}
	return nil
}

// ReadSysctl returns the current runtime value of a kernel parameter,
// trimmed of trailing whitespace (procfs values carry a trailing
// newline).
func ReadSysctl(key string) (string, error) {
	p, err := SysctlPath(key)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("kernelio: read %s: %w", p, err)
	}
	return strings.TrimSpace(string(b)), nil
}
