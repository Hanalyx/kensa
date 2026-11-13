package auditruleset

import (
	"strings"
	"testing"
)

// @spec handler-audit-rule-set
// @ac AC-01
func TestMergeRuleLines_AppendsPreservingSiblings(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-01", func(t *testing.T) {})
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-01")

	// A shared drop-in already owning a sibling rule (the 50-privileged.rules
	// case: 27 rules share one file).
	existing := managedHeader + "\n-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged\n"
	ruleB := []string{"-a always,exit -F path=/usr/bin/su -F perm=x -k privileged"}

	merged, added := mergeRuleLines(existing, ruleB)

	if !strings.Contains(merged, "/usr/bin/sudo") {
		t.Errorf("merge dropped the sibling rule (the clobber): %q", merged)
	}
	if !strings.Contains(merged, "/usr/bin/su") {
		t.Errorf("merge did not add the new rule: %q", merged)
	}
	if len(added) != 1 || !strings.Contains(added[0], "/usr/bin/su") {
		t.Errorf("added = %v, want the single new rule line", added)
	}
}

// @spec handler-audit-rule-set
// @ac AC-01
func TestMergeRuleLines_Idempotent(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-01", func(t *testing.T) {})
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-01")

	rule := []string{"-w /etc/passwd -p wa -k identity"}
	first, added1 := mergeRuleLines("", rule)
	if len(added1) != 1 {
		t.Fatalf("first merge added = %v, want 1", added1)
	}
	if !strings.HasPrefix(first, managedHeader) {
		t.Errorf("new file must start with the managed header: %q", first)
	}
	second, added2 := mergeRuleLines(first, rule)
	if len(added2) != 0 {
		t.Errorf("re-merging the same rule must add nothing; added=%v", added2)
	}
	if second != first {
		t.Errorf("re-merge changed content:\n first=%q\nsecond=%q", first, second)
	}
}

// @spec handler-audit-rule-set
// @ac AC-02
func TestRestoreFile_RemovesOwnKeepsSiblings(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-02", func(t *testing.T) {})
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-02")

	const su = "-a always,exit -F path=/usr/bin/su -F perm=x -k privileged"
	// Kensa created the file with the su rule; a sibling merged sudo after.
	current := managedHeader + "\n" + su + "\n" +
		"-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged\n"
	r := restoreFile(current, true, "", false, true, []string{su})
	if r.remove || strings.Contains(r.content, "/usr/bin/su ") {
		t.Errorf("rolled-back rule still present or file removed: %+v", r)
	}
	if !strings.Contains(r.content, "/usr/bin/sudo") {
		t.Errorf("sibling rule was wrongly removed (the clobber, in reverse): %q", r.content)
	}
}

// @spec handler-audit-rule-set
// @ac AC-02
func TestRestoreFile_RemovesFileKensaCreated(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-02", func(t *testing.T) {})
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-02")

	const w = "-w /etc/passwd -p wa -k identity"
	current := managedHeader + "\n" + w + "\n"
	if r := restoreFile(current, true, "", false, true, []string{w}); !r.remove {
		t.Errorf("a file Kensa created and nothing else touched must be removed: %+v", r)
	}
}

// A change after Apply that is not an append keeps every byte but the lines
// Apply added; a file that is gone at rollback stays gone; a pre-state with
// no capture of the file removes it only when nothing but Kensa's header is
// left.
//
// @spec handler-audit-rule-set
// @ac AC-07
func TestRestoreFile_OtherChanges(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-07", func(t *testing.T) {
		const ours = "-a always,exit -F arch=b64 -S execve -k k"
		prior := "-a always,exit -F arch=b64 -S chmod -k other\n"
		// An operator edited a line above ours.
		current := "-a always,exit -F arch=b64 -S chmod -k other_renamed\n" + ours + "\n"
		if r := restoreFile(current, true, prior, true, true, []string{ours}); r.remove ||
			r.content != "-a always,exit -F arch=b64 -S chmod -k other_renamed\n" {
			t.Errorf("edited file: %+v", r)
		}
		if r := restoreFile("", false, prior, true, true, []string{ours}); !r.remove {
			t.Errorf("a file gone at rollback must stay gone: %+v", r)
		}
		header := managedHeader + "\n" + ours + "\n"
		if r := restoreFile(header, true, "", false, false, []string{ours}); !r.remove {
			t.Errorf("no capture, only the header left: %+v", r)
		}
		comment := "# operator\n" + ours + "\n"
		if r := restoreFile(comment, true, "", false, false, []string{ours}); r.remove || r.content != "# operator\n" {
			t.Errorf("no capture, an operator comment left: %+v", r)
		}
	})
}
