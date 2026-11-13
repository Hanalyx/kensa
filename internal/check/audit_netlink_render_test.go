package check

import (
	"context"
	"encoding/binary"
	"io/fs"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
)

// RuleText renders a netlink rule as auditctl syntax, except that a watch
// keeps its field type as an explicit path= or dir=. Every rule in the
// netlink captures, rendered from the wire netlink builds, compares with
// the line auditctl -l printed for it without a provable difference. A rule
// whose list word has the prepend bit set renders as the rule without it;
// the kernel measured does not return the bit, so this pins the defensive
// mask.
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

// stubTransport answers every command with one result.
type stubTransport struct{ out string }

func (s stubTransport) Run(context.Context, string) (*api.CommandResult, error) {
	return &api.CommandResult{Stdout: s.out}, nil
}
func (stubTransport) Put(context.Context, string, string, fs.FileMode) error { return nil }
func (stubTransport) Get(context.Context, string, string) error              { return nil }
func (stubTransport) Close() error                                           { return nil }
func (stubTransport) ControlChannelSensitive() bool                          { return false }

// Against a loaded rule, a source -w whose path's type now differs from the
// field auditctl chose at boot is Unresolved, not Distinct; between two
// source lines the mismatch stays Distinct. AuditLoadedAmong reads a listed
// line it cannot parse as possibly the rule.
//
// @spec check-audit-rule-match
// @ac AC-22
func TestAuditLoaded_BootTypeAndUnreadableLines(t *testing.T) {
	t.Run("check-audit-rule-match/AC-22", func(t *testing.T) {
		target := testAuditTarget()
		target.Paths["/var/run/faillock"] = AuditPathDir
		const watch = "-w /var/run/faillock -p wa -k logins"
		const loadedPath = "-a always,exit -S all -F path=/var/run/faillock -F perm=wa -F key=logins"
		if id, why := AuditLoadedIdentity(watch, loadedPath, target); id != AuditUnresolved {
			t.Errorf("source -w (dir now) vs loaded path=: %v (%s), want Unresolved", id, why)
		}
		if id, _ := AuditRuleIdentity(watch, "-a always,exit -F path=/var/run/faillock -F perm=wa -k logins", target); id != AuditDistinct {
			t.Errorf("source -w (dir now) vs source path=: %v, want Distinct", id)
		}
		probe := "machine\tx86_64\nauditctl\tauditctl version 4.0.3\n"
		line, id, why, err := AuditLoadedAmong(context.Background(), stubTransport{probe},
			[]string{"-a always,exit -F arch=b64 -S execve -k exec"}, []string{"No rules", "-x not a rule"})
		if err != nil || id != AuditUnresolved || line == "" {
			t.Errorf("unreadable listed line: line=%q id=%v why=%q err=%v, want Unresolved", line, id, why, err)
		}
		if _, id, _, _ := AuditLoadedAmong(context.Background(), stubTransport{probe},
			[]string{"-a always,exit -F arch=b64 -S execve -k exec"}, []string{"No rules"}); id != AuditDistinct {
			t.Errorf("No rules: %v, want Distinct", id)
		}
	})
}
