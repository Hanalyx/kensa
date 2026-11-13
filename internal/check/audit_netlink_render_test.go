package check

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/internal/agent/auditnl"
)

// RuleText renders a netlink rule as auditctl syntax, except that a watch
// keeps its field type as an explicit path= or dir=. Every rule in the
// netlink captures, rendered from the wire netlink builds, compares with
// the line auditctl -l printed for it without a provable difference. A rule
// added with -A, which the kernel returns with the prepend bit set in its
// list word, renders as the -a rule.
//
// @spec check-audit-rule-match
// @ac AC-17
func TestAuditIdentity_NetlinkRendering(t *testing.T) {
	t.Run("check-audit-rule-match/AC-17", func(t *testing.T) {
		for line, want := range map[string]string{
			"-a always,exit -F path=/etc/shadow -F perm=wa -k k":   "-a always,exit -S all -F path=/etc/shadow -F perm=wa -F key=k",
			"-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k k": "-a always,exit -S all -F dir=/etc/sudoers.d -F perm=wa -F key=k",
			"-a never,exit -F path=/etc/shadow -F perm=wa -k k":    "-a never,exit -S all -F path=/etc/shadow -F perm=wa -F key=k",
		} {
			w, err := auditnl.BuildRule(line)
			if err != nil {
				t.Fatal(err)
			}
			got, err := auditnl.RuleText(w)
			if err != nil || got != want {
				t.Errorf("RuleText(%q) = %q, %v; want %q", line, got, err, want)
			}
		}
		target := testAuditTarget()
		for _, name := range []string{"audit-4.0.3-netlink.tsv", "audit-3.1.5-netlink.tsv"} {
			for _, row := range capturedPrints(t, name) {
				w, err := auditnl.BuildRule(row[0])
				if err != nil {
					t.Fatalf("build %q: %v", row[0], err)
				}
				text, err := auditnl.RuleText(w)
				if err != nil {
					t.Fatalf("render %q: %v", row[0], err)
				}
				if isNeverRule(row[0]) {
					// auditctl -l prints this as an always watch; netlink keeps "never".
					if !strings.HasPrefix(text, "-a never,exit") {
						t.Errorf("%s: never rule %q renders as %q", name, row[0], text)
					}
					continue
				}
				a, b := parseAuditK(text, auditLoaded), parseAuditK(row[1], auditLoaded)
				if id, why := auditIdentity(a, b, target); id == AuditDistinct {
					t.Errorf("%s: %q renders as %q, which differs from the listing %q (%s)", name, row[0], text, row[1], why)
				}
			}
		}
		const exitRule = "-a always,exit -F arch=b64 -S execve -k exec"
		w, err := auditnl.BuildRule(exitRule)
		if err != nil {
			t.Fatal(err)
		}
		plain, _ := auditnl.RuleText(w)
		binary.NativeEndian.PutUint32(w, binary.NativeEndian.Uint32(w)|0x10)
		prepended, err := auditnl.RuleText(w)
		if err != nil || prepended != plain {
			t.Errorf("prepend-bit rule renders as %q, %v; want %q", prepended, err, plain)
		}
	})
}

// The kernel keeps a rule's keys as one string joined by \x01. A netlink
// listing returns that string, and auditctl -l prints one key flag per key,
// so both forms of a two-key rule are the same kernel rule as the source
// line; keys in another order are not.
//
// @spec check-audit-rule-match
// @ac AC-21
func TestAuditIdentity_TwoKeys(t *testing.T) {
	t.Run("check-audit-rule-match/AC-21", func(t *testing.T) {
		target := testAuditTarget()
		for _, c := range []struct {
			source, listed string
			want           AuditIdentity
		}{
			// The auditctl -l form: one -F key= per key, as auditctl-listing.c
			// prints a key string split on AUDIT_KEY_SEPARATOR.
			{"-a always,exit -F arch=b64 -S execve -k a -k b",
				"-a always,exit -F arch=b64 -S execve -F key=a -F key=b", AuditSame},
			{"-a always,exit -F arch=b64 -S execve -k a -k b",
				"-a always,exit -F arch=b64 -S execve -F key=b -F key=a", AuditDistinct},
			{"-a always,exit -F arch=b64 -S execve -k a",
				"-a always,exit -F arch=b64 -S execve -F key=a -F key=b", AuditDistinct},
		} {
			if id, why := AuditLoadedIdentity(c.source, c.listed, target); id != c.want {
				t.Errorf("%q vs %q = %v (%s), want %v", c.source, c.listed, id, why, c.want)
			}
		}
		// The netlink form, rendered from the wire BuildRule makes for each
		// source line: a watch and a syscall rule.
		for _, source := range []string{
			"-a always,exit -F arch=b64 -S execve -k a -k b",
			"-a always,exit -F path=/etc/shadow -F perm=wa -k a -k b",
		} {
			w, err := auditnl.BuildRule(source)
			if err != nil {
				t.Fatal(err)
			}
			text, err := auditnl.RuleText(w)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text, "a\x01b") {
				t.Fatalf("%q renders as %q, without the joined key string", source, text)
			}
			if id, why := AuditLoadedIdentity(source, text, target); id == AuditDistinct {
				t.Errorf("%q vs its netlink rendering %q = Distinct (%s)", source, text, why)
			}
			// Coverage reads keys as a set, so the joined string must split:
			// a requirement keyed b alone is carried by the two-key rule.
			if got := parseAuditK(text, auditLoaded).keys; !auditKeysCover([]string{"b"}, got) {
				t.Errorf("%q: keys %q do not carry b", text, got)
			}
		}
	})
}
