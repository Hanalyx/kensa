package valueguard

import "testing"

// @spec security-value-hardening
// @ac AC-02
func TestNoControlChars(t *testing.T) {
	t.Run("security-value-hardening/AC-02", func(t *testing.T) {})
	t.Log("// @spec security-value-hardening")
	t.Log("// @ac AC-02")
	ok := []string{"", "1", "0755", "on", "/dev/sda1", "aes256-ctr,aes128-gcm", "a b c (spaces are fine)"}
	for _, v := range ok {
		if err := NoControlChars("f", v); err != nil {
			t.Errorf("NoControlChars(%q) = %v, want nil", v, err)
		}
	}
	bad := []string{"1\nmalicious=1", "x\r", "a\x00b", "line1\nline2", "tab\there"}
	for _, v := range bad {
		if err := NoControlChars("f", v); err == nil {
			t.Errorf("NoControlChars(%q) = nil, want error (control char must be rejected)", v)
		}
	}
}

// @spec security-value-hardening
// @ac AC-01
func TestGrubParamValue(t *testing.T) {
	t.Run("security-value-hardening/AC-01", func(t *testing.T) {})
	t.Log("// @spec security-value-hardening")
	t.Log("// @ac AC-01")
	ok := []string{"1", "8192", "none", "on", "P", "ttyS0,115200", "root=/dev/sda1", "1.2.3-4"}
	for _, v := range ok {
		if err := GrubParamValue(v); err != nil {
			t.Errorf("GrubParamValue(%q) = %v, want nil (real kernel-param values must pass)", v, err)
		}
	}
	// sed/shell specials and newlines that would corrupt the root-run grub edit.
	bad := []string{`1|rm -rf`, `a&b`, `x\ny`, "v\nGRUB_CMDLINE=evil", `a b`, `"quoted"`, `$(id)`, "`id`"}
	for _, v := range bad {
		if err := GrubParamValue(v); err == nil {
			t.Errorf("GrubParamValue(%q) = nil, want error (dangerous char must be rejected)", v)
		}
	}
}
