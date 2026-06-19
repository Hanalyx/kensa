package check

import "testing"

// @spec comparator-engine
// @ac AC-01
// @ac AC-02
func TestCompareValue(t *testing.T) {
	t.Run("comparator-engine/AC-01", func(t *testing.T) {})
	t.Run("comparator-engine/AC-02", func(t *testing.T) {})

	cases := []struct {
		got, exp, cmp string
		insensitive   bool
		want          bool
	}{
		// default + == (config_value is case-insensitive)
		{"keep_logs", "keep_logs", "", true, true},
		{"KEEP_LOGS", "keep_logs", "==", true, true},   // EqualFold
		{"KEEP_LOGS", "keep_logs", "==", false, false}, // sysctl exact: case-sensitive
		{"a", "b", "!=", true, true},
		{"a", "a", "!=", true, false},
		// numeric comparators
		{"60", "365", "<=", true, true},
		{"60", "10", "<=", true, false},
		{"500", "365", ">=", true, true},
		{"5", "5", "<", true, false},
		{"4", "5", "<", true, true},
		{"6", "5", ">", true, true},
		// non-numeric operand under a numeric comparator -> false (not error)
		{"abc", "5", "<=", true, false},
		{"5", "abc", ">=", true, false},
		// unknown comparator -> false (defensive; validator rejects at load)
		{"5", "5", "~=", true, false},
	}
	for _, c := range cases {
		if got := compareValue(c.got, c.exp, c.cmp, c.insensitive); got != c.want {
			t.Errorf("compareValue(%q,%q,%q,insensitive=%v)=%v want %v", c.got, c.exp, c.cmp, c.insensitive, got, c.want)
		}
	}
}

// @spec comparator-engine
// @ac AC-03
func TestComparatorInContract(t *testing.T) {
	t.Run("comparator-engine/AC-03", func(t *testing.T) {})
	for _, method := range []string{"config_value", "sysctl_value"} {
		c := CheckContracts[method]
		found := false
		for _, o := range c.Optional {
			if o == "comparator" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s contract must list 'comparator' as Optional now that the engine reads it", method)
		}
	}
}
