package check

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
)

// auditProbePrefix is how every AuditTargetProbe command starts.
const auditProbePrefix = "printf 'machine"

// testAuditTarget is the host the audit tests run against unless they say
// otherwise: x86_64 with audit-4.0.3, root resolvable through files, and
// the directories the corpus watches present as directories. Any other
// probed path answers as an existing regular file.
func testAuditTarget() *AuditTarget {
	paths := map[string]AuditPathKind{}
	for _, d := range []string{"/etc/sudoers.d", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
		"/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron", "/var/run/faillock", "/var/log/faillock",
		"/var/log/journal", "/etc/selinux", "/usr/share/selinux", "/etc/audit", "/var/log/audit"} {
		paths[d] = AuditPathDir
	}
	for _, f := range []string{"/etc/shadow", "/etc/passwd", "/etc/group", "/etc/gshadow", "/etc/sudoers",
		"/etc/security/opasswd", "/etc/hosts", "/var/log/lastlog", "/var/log/sudo.log", "/var/run/utmp",
		"/var/log/wtmp", "/var/log/btmp", "/etc/kensa-probe"} {
		paths[f] = AuditPathOther
	}
	return &AuditTarget{Machine: "x86_64", AuditctlVersion: "4.0.3",
		UIDs: map[string]int64{"root": 0}, GIDs: map[string]int64{"root": 0}, Paths: paths}
}

var (
	fakeProbePathRe  = regexp.MustCompile(`p='([^']*)';`)
	fakeProbeUserRe  = regexp.MustCompile(`getent -s files passwd '([^']*)'`)
	fakeProbeGroupRe = regexp.MustCompile(`getent -s files group '([^']*)'`)
)

// fakeAuditProbe answers an AuditTargetProbe command the way a host with
// target t would. A nil t is testAuditTarget. A probed path t does not name
// answers "other"; set its kind to "" in t.Paths to make it unknown.
func fakeAuditProbe(cmd string, t *AuditTarget) string {
	if t == nil {
		t = testAuditTarget()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "machine\t%s\n", t.Machine)
	fmt.Fprintf(&b, "auditctl\tauditctl version %s\n", t.AuditctlVersion)
	for _, m := range fakeProbeUserRe.FindAllStringSubmatch(cmd, -1) {
		if n, ok := t.UIDs[m[1]]; ok {
			fmt.Fprintf(&b, "uid\t%s\t%d\n", m[1], n)
		}
	}
	for _, m := range fakeProbeGroupRe.FindAllStringSubmatch(cmd, -1) {
		if n, ok := t.GIDs[m[1]]; ok {
			fmt.Fprintf(&b, "gid\t%s\t%d\n", m[1], n)
		}
	}
	for _, m := range fakeProbePathRe.FindAllStringSubmatch(cmd, -1) {
		k, ok := t.Paths[m[1]]
		if !ok {
			k = AuditPathOther
		}
		if k != "" {
			fmt.Fprintf(&b, "path\t%s\t%s\n", m[1], k)
		}
	}
	return b.String()
}

// guardRefuses reports whether the audit_rule_set guard would refuse to
// write rule next to the rules.d line onDisk on testAuditTarget.
func guardRefuses(rule, onDisk string) bool {
	id, _ := AuditRuleIdentity(rule, onDisk, testAuditTarget())
	return id != AuditDistinct
}

// netlinkFake is a fakeTransport that also offers audit netlink, as the
// agent transport does. Its kernel holds the rules built from lines, each
// written with an explicit path= or dir= field so the field type does not
// depend on the machine running the test.
type netlinkFake struct {
	*fakeTransport
	wires [][]byte
}

func newNetlinkFake(t interface{ Fatalf(string, ...any) }, auditctlListing string, lines ...string) *netlinkFake {
	f := &netlinkFake{fakeTransport: &fakeTransport{cmdResult: map[string]api.CommandResult{
		"auditctl -l": result(0, auditctlListing)}}}
	for _, l := range lines {
		w, err := auditnl.BuildRule(l)
		if err != nil {
			t.Fatalf("build %q: %v", l, err)
		}
		f.wires = append(f.wires, w)
	}
	return f
}

func (f *netlinkFake) AuditClient() (auditnl.AuditClient, error) {
	return netlinkFakeClient{f.wires}, nil
}

type netlinkFakeClient struct{ wires [][]byte }

func (c netlinkFakeClient) AddRule([]byte) error        { return nil }
func (c netlinkFakeClient) DeleteRule([]byte) error     { return nil }
func (c netlinkFakeClient) GetRules() ([][]byte, error) { return c.wires, nil }
func (c netlinkFakeClient) GetStatus() (int, error)     { return 1, nil }
func (c netlinkFakeClient) Close() error                { return nil }
