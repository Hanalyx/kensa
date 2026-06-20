package auditnl_test

import (
	"reflect"
	"testing"

	"github.com/Hanalyx/kensa/internal/agent/auditnl"
)

// BuildRule parses both watch and syscall auditctl syntax into non-empty
// wire format, and rejects a malformed line.
//
// @spec auditnl-rule-set
// @ac AC-01
func TestBuildRule(t *testing.T) {
	t.Run("auditnl-rule-set/AC-01", func(t *testing.T) {})
	for _, line := range []string{
		"-w /etc/passwd -p wa -k identity",
		"-a always,exit -F arch=b64 -S execve -k exec",
	} {
		wire, err := auditnl.BuildRule(line)
		if err != nil {
			t.Errorf("BuildRule(%q): %v", line, err)
		}
		if len(wire) == 0 {
			t.Errorf("BuildRule(%q): empty wire", line)
		}
	}
	// Deterministic: same line → same wire (the equality basis for capture).
	a, _ := auditnl.BuildRule("-w /etc/passwd -p wa -k identity")
	b, _ := auditnl.BuildRule("-w /etc/passwd -p wa -k identity")
	if !reflect.DeepEqual(a, b) {
		t.Error("BuildRule is not deterministic")
	}
	if _, err := auditnl.BuildRule("this is not an audit rule"); err == nil {
		t.Error("BuildRule should reject a malformed line")
	}
}

// RuleLines drops blanks, comments, and whitespace.
//
// @spec auditnl-rule-set
// @ac AC-01
func TestRuleLines(t *testing.T) {
	t.Run("auditnl-rule-set/AC-01", func(t *testing.T) {})
	body := "# Managed by Kensa.\n\n  -w /etc/passwd -p wa -k identity  \n# comment\n-w /etc/group -p wa -k identity\n"
	got := auditnl.RuleLines(body)
	want := []string{"-w /etc/passwd -p wa -k identity", "-w /etc/group -p wa -k identity"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RuleLines = %v, want %v", got, want)
	}
}
