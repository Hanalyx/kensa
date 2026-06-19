package kernelio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// @spec kernelio-sysctl
// @ac AC-01
func TestSysctlPath(t *testing.T) {
	t.Run("kernelio-sysctl/AC-01", func(t *testing.T) {})
	orig := procSysRoot
	procSysRoot = "/proc/sys"
	defer func() { procSysRoot = orig }()

	if got, err := SysctlPath("net.ipv4.ip_forward"); err != nil || got != "/proc/sys/net/ipv4/ip_forward" {
		t.Errorf("SysctlPath = (%q, %v), want /proc/sys/net/ipv4/ip_forward", got, err)
	}
	for _, bad := range []string{"", "net/ipv4/ip_forward", "../etc/passwd", "..", "a\x00b"} {
		if _, err := SysctlPath(bad); !errors.Is(err, ErrInvalidSysctlKey) {
			t.Errorf("SysctlPath(%q) err = %v, want ErrInvalidSysctlKey", bad, err)
		}
	}
}

// @spec kernelio-sysctl
// @ac AC-02
func TestWriteReadSysctl(t *testing.T) {
	t.Run("kernelio-sysctl/AC-02", func(t *testing.T) {})
	root := t.TempDir()
	orig := procSysRoot
	procSysRoot = root
	defer func() { procSysRoot = orig }()

	// procfs files pre-exist; WriteSysctl is O_WRONLY (no create), so
	// stage the file as the kernel would.
	if err := os.MkdirAll(filepath.Join(root, "net", "ipv4"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net", "ipv4", "ip_forward"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteSysctl("net.ipv4.ip_forward", "0"); err != nil {
		t.Fatalf("WriteSysctl: %v", err)
	}
	got, err := ReadSysctl("net.ipv4.ip_forward")
	if err != nil {
		t.Fatalf("ReadSysctl: %v", err)
	}
	if got != "0" {
		t.Errorf("ReadSysctl = %q, want 0", got)
	}

	// A nonexistent key fails loudly (O_WRONLY, no create).
	if err := WriteSysctl("net.ipv4.nonexistent_param", "1"); err == nil {
		t.Error("WriteSysctl to a nonexistent key should error")
	}
	// An invalid key is rejected before any IO.
	if err := WriteSysctl("../escape", "1"); !errors.Is(err, ErrInvalidSysctlKey) {
		t.Errorf("WriteSysctl invalid key err = %v, want ErrInvalidSysctlKey", err)
	}
}

// @spec kernelio-sysctl
// @ac AC-03
func TestReadFileIfExists(t *testing.T) {
	t.Run("kernelio-sysctl/AC-03", func(t *testing.T) {})
	dir := t.TempDir()
	p := filepath.Join(dir, "99-kensa.conf")

	// Absent.
	if c, existed, err := ReadFileIfExists(p); err != nil || existed || c != "" {
		t.Errorf("absent: got (%q, %v, %v), want (\"\", false, nil)", c, existed, err)
	}
	// Present.
	if err := os.WriteFile(p, []byte("body\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c, existed, err := ReadFileIfExists(p); err != nil || !existed || c != "body\n" {
		t.Errorf("present: got (%q, %v, %v), want (\"body\\n\", true, nil)", c, existed, err)
	}
}
