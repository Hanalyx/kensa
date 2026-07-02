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
func TestRemoveRuleLines_RemovesOwnKeepsSiblings(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-02", func(t *testing.T) {})
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-02")

	content := managedHeader + "\n" +
		"-a always,exit -F path=/usr/bin/sudo -F perm=x -k privileged\n" +
		"-a always,exit -F path=/usr/bin/su -F perm=x -k privileged\n"
	// Roll back only the su rule.
	reduced, remaining := removeRuleLines(content, []string{"-a always,exit -F path=/usr/bin/su -F perm=x -k privileged"})

	if strings.Contains(reduced, "/usr/bin/su ") || strings.Contains(reduced, "path=/usr/bin/su ") {
		t.Errorf("rolled-back rule still present: %q", reduced)
	}
	if !strings.Contains(reduced, "/usr/bin/sudo") {
		t.Errorf("sibling rule was wrongly removed (the clobber, in reverse): %q", reduced)
	}
	if !remaining {
		t.Error("remaining should be true — the sibling rule is still there")
	}
}

// @spec handler-audit-rule-set
// @ac AC-02
func TestRemoveRuleLines_EmptyWhenLastRuleRemoved(t *testing.T) {
	t.Run("handler-audit-rule-set/AC-02", func(t *testing.T) {})
	t.Log("// @spec handler-audit-rule-set")
	t.Log("// @ac AC-02")

	content := managedHeader + "\n-w /etc/passwd -p wa -k identity\n"
	_, remaining := removeRuleLines(content, []string{"-w /etc/passwd -p wa -k identity"})
	if remaining {
		t.Error("remaining should be false once the only rule line is removed (file can be deleted)")
	}
}
