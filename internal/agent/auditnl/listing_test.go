package auditnl

import (
	"encoding/binary"
	"testing"
)

// corruptWire returns line's wire with its list word set to list and its
// first field operator set to a value ToCommandLine does not know.
func corruptWire(t *testing.T, line string, list uint32) []byte {
	t.Helper()
	w, err := BuildRule(line)
	if err != nil {
		t.Fatal(err)
	}
	binary.NativeEndian.PutUint32(w[0:], list)
	binary.NativeEndian.PutUint32(w[12+3*256:], 0x7fffffff)
	return w
}

// RulesText fails on an exit-list rule it cannot render, and leaves out a
// rule on another list, naming the list.
//
// @spec auditnl-rule-set
// @ac AC-11
func TestRulesText_UnrenderableRules(t *testing.T) {
	t.Run("auditnl-rule-set/AC-11", func(t *testing.T) {
		const line = "-a always,exit -F arch=b64 -S chmod -k other"
		good, _ := BuildRule("-a always,exit -F arch=b64 -S execve -k exec")
		for _, c := range []struct {
			list    uint32
			wantErr bool
			skipped string
		}{
			{4, true, ""},
			{4 | 0x10, true, ""},
			{6, false, "filesystem"},
			{9, false, "list 9"},
		} {
			f := NewFakeAudit()
			f.Loaded["good"] = good
			f.Loaded["bad"] = corruptWire(t, line, c.list)
			c2, _ := f.AuditClient()
			texts, skipped, err := RulesText(c2)
			if (err != nil) != c.wantErr {
				t.Errorf("list %#x: err=%v, want error %v", c.list, err, c.wantErr)
				continue
			}
			if !c.wantErr && (len(texts) != 1 || len(skipped) != 1 || skipped[0] != c.skipped) {
				t.Errorf("list %#x: texts=%q skipped=%q, want one text and skipped [%s]", c.list, texts, skipped, c.skipped)
			}
		}
	})
}
