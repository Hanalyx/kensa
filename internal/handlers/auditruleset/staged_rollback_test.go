package auditruleset_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/agent/auditnl"
	"github.com/Hanalyx/kensa/internal/check"
	"github.com/Hanalyx/kensa/internal/engine"
	"github.com/Hanalyx/kensa/internal/handlers/auditruleset"
)

// bootRow is one captured rule: the line as a rules.d file holds it, and the
// line auditctl -l printed after auditctl loaded it, as augenrules does at
// boot.
type bootRow struct{ file, source, listed, version string }

// bootRows reads the captured auditctl loads whose listing is a syscall rule.
// A row whose listing is -w is left out: rebuilding its wire would stat the
// path on the test machine. A never row is left out: auditctl -l prints it
// as an always watch, so its listing does not rebuild the rule.
func bootRows(t *testing.T) []bootRow {
	t.Helper()
	var rows []bootRow
	for file, version := range map[string]string{
		"audit-4.0.3-auditctl.tsv": "4.0.3",
		"audit-3.1.5-auditctl.tsv": "3.1.5",
	} {
		b, err := os.ReadFile("../../check/testdata/auditctl/" + file)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, "\t")
			if len(f) != 2 || strings.HasPrefix(l, "#") || strings.HasPrefix(f[1], "-w ") ||
				strings.Contains(f[0], "never,") {
				continue
			}
			rows = append(rows, bootRow{file, f[0], f[1], version})
		}
	}
	if len(rows) == 0 {
		t.Fatal("no captured rows")
	}
	return rows
}

// answerProbe answers the host-facts probe the staged rollback runs for lines
// as an x86_64 host with the given audit version.
func answerProbe(f *auditnl.FakeAuditTransport, version string, lines ...string) {
	runResults(f)[check.AuditTargetProbe(lines)] = &api.CommandResult{
		Stdout: "machine\tx86_64\nauditctl\tauditctl version " + version + "\n",
	}
}

// runResults returns the fake's command results, made on first use.
func runResults(f *auditnl.FakeAuditTransport) map[string]*api.CommandResult {
	if f.RunResults == nil {
		f.RunResults = map[string]*api.CommandResult{}
	}
	return f.RunResults
}

// stagedNetlink captures and applies source on an immutable host, so Apply
// stages it, and returns the pre-state.
func stagedNetlink(t *testing.T, f *auditnl.FakeAuditTransport, source string) *api.PreState {
	t.Helper()
	f.Enabled = 2
	h := auditruleset.New()
	params := api.Params{"rule": source, "persist_file": auditPath}
	pre, err := h.Capture(context.Background(), f, params)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	res, err := h.Apply(context.Background(), f, params, nil)
	if err != nil || !res.Success || !res.Staged {
		t.Fatalf("Apply: err=%v res=%+v", err, res)
	}
	return pre
}

// loadWire puts wire in the fake kernel, as auditd does at boot.
func loadWire(f *auditnl.FakeAuditTransport, wire []byte) {
	f.Loaded[hex.EncodeToString(wire)] = wire
}

// A staged rule that auditd loaded at boot is found in the running kernel
// although auditctl built it, not BuildRule. auditctl loads a perm rule with
// an arch as the syscall list it prints, so the boot wire is rebuilt from the
// captured auditctl -l line, and differs from BuildRule of the staged line.
// Every captured syscall row must give PartialRestore, never a clean
// restore. Before this change the wire compare found no match and reported
// a clean restore.
//
// @spec auditnl-rule-set
// @ac AC-10
func TestRollback_Netlink_StagedRuleLoadedAtBoot(t *testing.T) {
	t.Run("auditnl-rule-set/AC-10", func(t *testing.T) {
		differ := 0
		for _, r := range bootRows(t) {
			f := auditnl.NewFakeAudit()
			pre := stagedNetlink(t, f, r.source)
			boot, err := auditnl.BuildRule(r.listed)
			if err != nil {
				t.Fatalf("%s: build %q: %v", r.file, r.listed, err)
			}
			if staged, _ := auditnl.BuildRule(r.source); hex.EncodeToString(staged) != hex.EncodeToString(boot) {
				differ++
			}
			loadWire(f, boot)
			text, err := auditnl.RuleText(boot)
			if err != nil {
				t.Fatalf("%s: render %q: %v", r.file, r.listed, err)
			}
			answerProbe(f, r.version, r.source, text)
			rb, err := auditruleset.New().Rollback(context.Background(), f, pre)
			if err != nil {
				t.Fatalf("%s: Rollback: %v", r.file, err)
			}
			if rb.Success || !rb.PartialRestore || !strings.Contains(rb.Detail, "is loaded in the running kernel") {
				t.Errorf("%s: staged %q loaded at boot as %q: Success=%v Partial=%v detail=%q",
					r.file, r.source, r.listed, rb.Success, rb.PartialRestore, rb.Detail)
			}
			if _, ok := f.Files[auditPath]; ok {
				t.Errorf("%s: the drop-in was not removed", r.file)
			}
		}
		if differ == 0 {
			t.Error("no captured row has a boot wire that differs from BuildRule of the staged line; the test does not model the reboot")
		}
	})
}

// corrupt returns wire with its first field's operator set to a value the
// renderer does not know, and its list set to list, so RuleText fails.
func corrupt(t *testing.T, line string, list uint32) []byte {
	t.Helper()
	w, err := auditnl.BuildRule(line)
	if err != nil {
		t.Fatal(err)
	}
	ne := binary.NativeEndian
	ne.PutUint32(w[0:], list)
	ne.PutUint32(w[12+3*256:], 0x7fffffff) // fieldflags[0]
	if _, err := auditnl.RuleText(w); err == nil {
		t.Fatal("corrupted wire still renders")
	}
	return w
}

// Every read the staged netlink verdict depends on fails closed: a rule
// listing that cannot be read, an exit-list rule that cannot be rendered, a
// rule left out of the listing on the list of a staged line, and a host-facts
// probe that fails each give PartialRestore with a detail saying what could
// not be read. A rule on another list that cannot be rendered is left out
// when no staged line is on that list. A rule added with -A, which the
// kernel reports with the prepend bit set, is still found.
//
// @spec auditnl-rule-set
// @ac AC-11
func TestRollback_Netlink_StagedReadsFailClosed(t *testing.T) {
	t.Run("auditnl-rule-set/AC-11", func(t *testing.T) {
		const exitRule = "-a always,exit -F arch=b64 -S execve -k exec"
		const excludeRule = "-a always,exclude -F msgtype=CWD"
		run := func(name, source string, setup func(f *auditnl.FakeAuditTransport), wantPartial bool, wantDetail string) {
			t.Helper()
			f := auditnl.NewFakeAudit()
			pre := stagedNetlink(t, f, source)
			setup(f)
			rb, err := auditruleset.New().Rollback(context.Background(), f, pre)
			if err != nil {
				t.Fatalf("%s: Rollback: %v", name, err)
			}
			if rb.PartialRestore != wantPartial || rb.Success == wantPartial || !strings.Contains(rb.Detail, wantDetail) {
				t.Errorf("%s: Success=%v Partial=%v detail=%q; want Partial=%v and %q",
					name, rb.Success, rb.PartialRestore, rb.Detail, wantPartial, wantDetail)
			}
		}
		run("listing unreadable", exitRule, func(f *auditnl.FakeAuditTransport) {
			f.GetRulesErr = errors.New("netlink: no buffer space")
		}, true, "could not be read")
		run("exit-list rule unrenderable", exitRule, func(f *auditnl.FakeAuditTransport) {
			loadWire(f, corrupt(t, "-a always,exit -F arch=b64 -S chmod -k other", 4))
		}, true, "could not be read")
		run("filesystem-list rule unrenderable, staged rule on exit", exitRule, func(f *auditnl.FakeAuditTransport) {
			loadWire(f, corrupt(t, "-a always,exit -F arch=b64 -S chmod -k other", 6))
		}, false, "no staged rule loaded")
		run("exclude-list rule unrenderable, staged rule on exclude", excludeRule, func(f *auditnl.FakeAuditTransport) {
			loadWire(f, corrupt(t, excludeRule, 5))
		}, true, "exclude list")
		run("probe fails", exitRule, func(f *auditnl.FakeAuditTransport) {
			w, _ := auditnl.BuildRule(exitRule)
			loadWire(f, w)
			text, _ := auditnl.RuleText(w)
			runResults(f)[check.AuditTargetProbe([]string{exitRule, text})] = &api.CommandResult{ExitCode: 1, Stderr: "permission denied"}
		}, true, "host facts")
		run("rule added with -A reads back with the prepend bit", exitRule, func(f *auditnl.FakeAuditTransport) {
			w, _ := auditnl.BuildRule(exitRule)
			binary.NativeEndian.PutUint32(w, binary.NativeEndian.Uint32(w)|0x10)
			loadWire(f, w)
			text, err := auditnl.RuleText(w)
			if err != nil {
				t.Fatalf("prepend wire does not render: %v", err)
			}
			answerProbe(f, "4.0.3", exitRule, text)
		}, true, "is loaded in the running kernel")
		run("a rule on an unknown list unrenderable", exitRule, func(f *auditnl.FakeAuditTransport) {
			loadWire(f, corrupt(t, "-a always,exit -F arch=b64 -S chmod -k other", 9))
		}, true, "unknown filter list")
		run("an unrelated rule loaded", exitRule, func(f *auditnl.FakeAuditTransport) {
			w, _ := auditnl.BuildRule("-a always,exit -F arch=b64 -S execve -k other")
			loadWire(f, w)
		}, false, "no staged rule loaded")
	})
}

// A persist_only -e 2 staged on a mutable host takes effect at boot and
// cannot be undone until the next one, so a rollback after that reboot is a
// partial restore. A status that cannot be read is a partial restore too.
// When capture read the config as immutable already, the staged -e 2 changed
// nothing, and the rollback is clean.
//
// @spec auditnl-rule-set
// @ac AC-11
func TestRollback_Netlink_StagedImmutableDirective(t *testing.T) {
	t.Run("auditnl-rule-set/AC-11", func(t *testing.T) {
		params := api.Params{"rule": "-e 2", "persist_file": "/etc/audit/rules.d/99-finalize.rules", "persist_only": true}
		run := func(name string, atCapture int, after func(f *auditnl.FakeAuditTransport), wantPartial bool) {
			t.Helper()
			f := auditnl.NewFakeAudit()
			f.Enabled = atCapture
			h := auditruleset.New()
			pre, err := h.Capture(context.Background(), f, params)
			if err != nil {
				t.Fatalf("%s: Capture: %v", name, err)
			}
			if res, err := h.Apply(context.Background(), f, params, nil); err != nil || !res.Staged {
				t.Fatalf("%s: Apply: err=%v res=%+v", name, err, res)
			}
			after(f)
			rb, err := h.Rollback(context.Background(), f, pre)
			if err != nil {
				t.Fatalf("%s: Rollback: %v", name, err)
			}
			if rb.PartialRestore != wantPartial || rb.Success == wantPartial {
				t.Errorf("%s: Success=%v Partial=%v detail=%q, want Partial=%v", name, rb.Success, rb.PartialRestore, rb.Detail, wantPartial)
			}
		}
		run("mutable at capture, no reboot", 1, func(*auditnl.FakeAuditTransport) {}, false)
		run("mutable at capture, rebooted into enabled 2", 1, func(f *auditnl.FakeAuditTransport) { f.Enabled = 2 }, true)
		run("mutable at capture, status unreadable", 1, func(f *auditnl.FakeAuditTransport) {
			f.GetStatusErr = errors.New("netlink: timeout")
		}, true)
		run("immutable at capture", 2, func(*auditnl.FakeAuditTransport) {}, false)
	})
}

// failingTransport returns a transport error for one command.
type failingTransport struct {
	*engine.FakeTransport
	cmd string
}

func (f *failingTransport) Run(ctx context.Context, cmd string) (*api.CommandResult, error) {
	if cmd == f.cmd {
		return nil, errors.New("ssh: connection reset")
	}
	return f.FakeTransport.Run(ctx, cmd)
}

// stagedShellPre is the pre-state of a shell-path transaction that staged
// line on an immutable host.
func stagedShellPre(line string) *api.PreState {
	return &api.PreState{
		Mechanism: "audit_rule_set",
		Data: map[string]interface{}{
			"path":                       auditPath,
			"file_existed":               false,
			"prior_content":              "",
			"file_added_lines":           []string{line},
			"immutable_staged":           true,
			"audit_immutable_at_capture": true,
		},
	}
}

// The shell staged verdict reads auditctl -l and compares by kernel
// identity. A listing that cannot be read (non-zero exit, a transport error,
// no output) or a failed host-facts probe gives PartialRestore. "No rules"
// is a clean restore.
//
// @spec auditnl-rule-set
// @ac AC-11
func TestRollback_Shell_StagedReadsFailClosed(t *testing.T) {
	t.Run("auditnl-rule-set/AC-11", func(t *testing.T) {
		const staged = "-a always,exit -F arch=b64 -S execve -k exec"
		const listed = "-a always,exit -F arch=b64 -S execve -F key=exec"
		cases := []struct {
			name    string
			setup   func(tp *engine.FakeTransport)
			partial bool
			detail  string
		}{
			{"auditctl -l exits 1", func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{ExitCode: 1, Stderr: "Error sending rule list data request"}
			}, true, "could not be read"},
			{"auditctl -l prints nothing", func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{}
			}, true, "printed nothing"},
			{"probe fails", func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{Stdout: listed + "\n"}
				tp.Results[check.AuditTargetProbe([]string{staged, listed})] = &api.CommandResult{ExitCode: 126}
			}, true, "host facts"},
			{"rule loaded", func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{Stdout: listed + "\n"}
				measuredHost(tp, staged, listed)
			}, true, "is loaded in the running kernel"},
			{"No rules", func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{Stdout: "No rules\n"}
			}, false, "no staged rule loaded"},
		}
		tp := &failingTransport{FakeTransport: engine.NewFakeTransport(), cmd: "auditctl -l"}
		rb, err := auditruleset.New().Rollback(context.Background(), tp, stagedShellPre(staged))
		if err != nil || rb.Success || !rb.PartialRestore || !strings.Contains(rb.Detail, "could not be read") {
			t.Errorf("auditctl -l transport error: err=%v Success=%v Partial=%v detail=%q", err, rb.Success, rb.PartialRestore, rb.Detail)
		}
		for _, c := range cases {
			tp := engine.NewFakeTransport()
			c.setup(tp)
			rb, err := auditruleset.New().Rollback(context.Background(), tp, stagedShellPre(staged))
			if err != nil {
				t.Fatalf("%s: Rollback: %v", c.name, err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial || !strings.Contains(rb.Detail, c.detail) {
				t.Errorf("%s: Success=%v Partial=%v detail=%q; want Partial=%v and %q",
					c.name, rb.Success, rb.PartialRestore, rb.Detail, c.partial, c.detail)
			}
		}
	})
}

// A committed shell rollback whose auditctl -s cannot be read verifies the
// unload through auditctl -l. A rule Apply added that is still loaded, a
// listing that cannot be read, and an added -e 2 each give PartialRestore;
// a listing without the rule is a clean restore.
//
// @spec auditnl-rule-set
// @ac AC-12
func TestRollback_Shell_CommittedStatusUnreadable(t *testing.T) {
	t.Run("auditnl-rule-set/AC-12", func(t *testing.T) {
		const added = "-a always,exit -F arch=b64 -S execve -k exec"
		const listed = "-a always,exit -F arch=b64 -S execve -F key=exec"
		pre := func(line string) *api.PreState {
			return &api.PreState{
				Mechanism: "audit_rule_set",
				Data: map[string]interface{}{
					"path":             auditPath,
					"file_existed":     false,
					"prior_content":    "",
					"file_added_lines": []string{line},
				},
			}
		}
		cases := []struct {
			name, line string
			setup      func(tp *engine.FakeTransport)
			partial    bool
		}{
			{"rule still loaded", added, func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{Stdout: listed + "\n"}
				measuredHost(tp, added, listed)
			}, true},
			{"listing unreadable", added, func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{ExitCode: 1}
			}, true},
			{"an -e 2 line was added", "-e 2", func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{Stdout: "No rules\n"}
			}, true},
			{"rule unloaded", added, func(tp *engine.FakeTransport) {
				tp.Results["auditctl -l"] = &api.CommandResult{Stdout: "-a always,exit -F arch=b64 -S chmod -F key=other\n"}
			}, false},
		}
		for _, c := range cases {
			tp := engine.NewFakeTransport()
			tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{ExitCode: 1}
			c.setup(tp)
			rb, err := auditruleset.New().Rollback(context.Background(), tp, pre(c.line))
			if err != nil {
				t.Fatalf("%s: Rollback: %v", c.name, err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial {
				t.Errorf("%s: Success=%v Partial=%v detail=%q, want Partial=%v", c.name, rb.Success, rb.PartialRestore, rb.Detail, c.partial)
			}
		}
	})
}

// A committed netlink rollback after a reboot on a mutable host: auditctl
// loaded the drop-in line at boot in its own form, so DeleteRule of the
// BuildRule wire gets ENOENT and leaves it loaded. The verify compares by
// kernel identity and reports PartialRestore. Before this change it reported
// "unloaded, verified".
//
// @spec auditnl-rule-set
// @ac AC-13
func TestRollback_Netlink_CommittedRuleReloadedAtBoot(t *testing.T) {
	t.Run("auditnl-rule-set/AC-13", func(t *testing.T) {
		rows := bootRows(t)
		checked := 0
		for _, r := range rows {
			staged, _ := auditnl.BuildRule(r.source)
			boot, err := auditnl.BuildRule(r.listed)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(staged) == hex.EncodeToString(boot) {
				continue
			}
			checked++
			f := auditnl.NewFakeAudit()
			f.Enabled = 1
			h := auditruleset.New()
			params := api.Params{"rule": r.source, "persist_file": auditPath}
			pre, err := h.Capture(context.Background(), f, params)
			if err != nil {
				t.Fatal(err)
			}
			if res, err := h.Apply(context.Background(), f, params, nil); err != nil || !res.Success || res.Staged {
				t.Fatalf("Apply: err=%v res=%+v", err, res)
			}
			// Reboot: the kernel starts empty and auditctl loads the drop-in line.
			f.Loaded = map[string][]byte{}
			loadWire(f, boot)
			text, _ := auditnl.RuleText(boot)
			answerProbe(f, r.version, r.source, text)
			rb, err := h.Rollback(context.Background(), f, pre)
			if err != nil {
				t.Fatal(err)
			}
			if rb.Success || !rb.PartialRestore || !strings.Contains(rb.Detail, "still loaded") {
				t.Errorf("%s: %q reloaded at boot as %q: Success=%v Partial=%v detail=%q",
					r.file, r.source, r.listed, rb.Success, rb.PartialRestore, rb.Detail)
			}
		}
		if checked == 0 {
			t.Fatal("no row has a boot wire that differs from BuildRule")
		}
	})
}

// shellPre is a shell-path pre-state with the given flags set.
func shellPre(line string, flags ...string) *api.PreState {
	data := map[string]interface{}{
		"path":             auditPath,
		"file_existed":     false,
		"prior_content":    "",
		"file_added_lines": []string{line},
	}
	for _, f := range flags {
		data[f] = true
	}
	return &api.PreState{Mechanism: "audit_rule_set", Data: data}
}

// A persist_only directive over the shell path is staged on any host. Its
// rollback removes the file and runs no load, since Apply ran none, and on a
// host capture read as mutable it reads the status: a reboot into enabled 2,
// or a status that cannot be read, is a partial restore. A control line no
// listing can show, such as -b 8192, is a partial restore on both shell
// paths.
//
// @spec auditnl-rule-set
// @ac AC-14
func TestRollback_Shell_PersistOnlyAndControlLines(t *testing.T) {
	t.Run("auditnl-rule-set/AC-14", func(t *testing.T) {
		h := auditruleset.New()
		params := api.Params{"rule": "-e 2", "persist_file": "/etc/audit/rules.d/99-finalize.rules", "persist_only": true}
		tp := engine.NewFakeTransport()
		tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: "enabled 1\nfailure 1\n"}
		pre, err := h.Capture(context.Background(), tp, params)
		if err != nil {
			t.Fatal(err)
		}
		if staged, _ := pre.Data["immutable_staged"].(bool); !staged {
			t.Fatal("a shell persist_only capture is not marked staged")
		}
		if po, _ := pre.Data["persist_only"].(bool); !po {
			t.Fatal("a shell persist_only capture is not marked persist_only")
		}
		for _, c := range []struct {
			name    string
			status  *api.CommandResult
			partial bool
		}{
			{"no reboot", &api.CommandResult{Stdout: "enabled 1\n"}, false},
			{"rebooted into enabled 2", &api.CommandResult{Stdout: "enabled 2\n"}, true},
			{"status unreadable", &api.CommandResult{ExitCode: 1}, true},
		} {
			rt := engine.NewFakeTransport()
			rt.Results["auditctl -s 2>/dev/null"] = c.status
			rt.Results["auditctl -l"] = &api.CommandResult{Stdout: "No rules\n"}
			rb, err := h.Rollback(context.Background(), rt, pre)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial {
				t.Errorf("%s: Success=%v Partial=%v detail=%q, want Partial=%v", c.name, rb.Success, rb.PartialRestore, rb.Detail, c.partial)
			}
			for _, cmd := range rt.Runs {
				if strings.Contains(cmd, "augenrules") {
					t.Errorf("%s: persist_only rollback ran a load: %q", c.name, cmd)
				}
			}
		}
		for name, pre := range map[string]*api.PreState{
			"staged":    shellPre("-b 8192", "immutable_staged", "audit_immutable_at_capture"),
			"committed": shellPre("-b 8192"),
		} {
			rt := engine.NewFakeTransport()
			rt.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: "enabled 1\n"}
			rt.Results["auditctl -l"] = &api.CommandResult{Stdout: "No rules\n"}
			rb, err := h.Rollback(context.Background(), rt, pre)
			if err != nil {
				t.Fatal(err)
			}
			if rb.Success || !rb.PartialRestore || !strings.Contains(rb.Detail, "-b 8192") {
				t.Errorf("%s -b 8192: Success=%v Partial=%v detail=%q", name, rb.Success, rb.PartialRestore, rb.Detail)
			}
		}
	})
}

// A committed shell rollback on a mutable host checks the listing as well:
// augenrules --load removes a rule only when the compiled rules start with
// -D. A rule still listed is a partial restore. A listed line the parser
// cannot read may be the rule, so it is one too.
//
// @spec auditnl-rule-set
// @ac AC-12
func TestRollback_Shell_CommittedMutableVerifiesListing(t *testing.T) {
	t.Run("auditnl-rule-set/AC-12", func(t *testing.T) {
		const added = "-a always,exit -F arch=b64 -S execve -k exec"
		const listed = "-a always,exit -F arch=b64 -S execve -F key=exec"
		for _, c := range []struct {
			name, listing string
			partial       bool
		}{
			{"rule still loaded", listed, true},
			{"unreadable listed line", "-x something unexpected", true},
			{"rule gone", "-a always,exit -F arch=b64 -S chmod -F key=other", false},
		} {
			tp := engine.NewFakeTransport()
			tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: "enabled 1\n"}
			tp.Results["auditctl -l"] = &api.CommandResult{Stdout: c.listing + "\n"}
			measuredHost(tp, added, listed)
			rb, err := auditruleset.New().Rollback(context.Background(), tp, shellPre(added))
			if err != nil {
				t.Fatal(err)
			}
			if rb.PartialRestore != c.partial || rb.Success == c.partial {
				t.Errorf("%s: Success=%v Partial=%v detail=%q, want Partial=%v", c.name, rb.Success, rb.PartialRestore, rb.Detail, c.partial)
			}
		}
	})
}

// A staged -w takes its field type from the path's type at rollback, but
// auditctl chose path= or dir= at boot, and the path may have changed type
// since (a tmpfs directory created after the audit rules load, or one removed
// since). A loaded rule of the other type may be the staged rule, so the
// rollback reports PartialRestore, never a clean restore.
//
// @spec auditnl-rule-set
// @ac AC-11
func TestRollback_Netlink_StagedWatchTypeChangedSinceBoot(t *testing.T) {
	t.Run("auditnl-rule-set/AC-11", func(t *testing.T) {
		const staged = "-w /var/run/faillock -p wa -k logins"
		for _, c := range []struct{ boot, kindNow string }{
			{"-a always,exit -S all -F path=/var/run/faillock -F perm=wa -F key=logins", "dir"},
			{"-a always,exit -S all -F dir=/var/run/faillock -F perm=wa -F key=logins", "missing"},
			{"-a always,exit -S all -F dir=/var/run/faillock -F perm=wa -F key=logins", "other"},
		} {
			f := auditnl.NewFakeAudit()
			pre := stagedNetlink(t, f, staged)
			w, err := auditnl.BuildRule(c.boot)
			if err != nil {
				t.Fatal(err)
			}
			loadWire(f, w)
			text, _ := auditnl.RuleText(w)
			runResults(f)[check.AuditTargetProbe([]string{staged, text})] = &api.CommandResult{
				Stdout: "machine\tx86_64\nauditctl\tauditctl version 4.0.3\npath\t/var/run/faillock\t" + c.kindNow + "\n",
			}
			rb, err := auditruleset.New().Rollback(context.Background(), f, pre)
			if err != nil {
				t.Fatal(err)
			}
			if rb.Success || !rb.PartialRestore {
				t.Errorf("boot %q, path now %s: Success=%v Partial=%v detail=%q", c.boot, c.kindNow, rb.Success, rb.PartialRestore, rb.Detail)
			}
		}
	})
}

// An auditctl -s that prints no "enabled" line is a status that cannot be
// read, so a committed shell rollback verifies through the listing.
//
// @spec auditnl-rule-set
// @ac AC-12
func TestRollback_Shell_StatusWithoutEnabledLine(t *testing.T) {
	t.Run("auditnl-rule-set/AC-12", func(t *testing.T) {
		const added = "-a always,exit -F arch=b64 -S execve -k exec"
		tp := engine.NewFakeTransport()
		tp.Results["auditctl -s 2>/dev/null"] = &api.CommandResult{Stdout: "garbage\n"}
		tp.Results["auditctl -l"] = &api.CommandResult{ExitCode: 1}
		rb, err := auditruleset.New().Rollback(context.Background(), tp, shellPre(added))
		if err != nil {
			t.Fatal(err)
		}
		if rb.Success || !rb.PartialRestore || !strings.Contains(rb.Detail, "no enabled line") {
			t.Errorf("Success=%v Partial=%v detail=%q", rb.Success, rb.PartialRestore, rb.Detail)
		}
	})
}
