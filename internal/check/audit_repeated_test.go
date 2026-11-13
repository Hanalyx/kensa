package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// A rule that gives arch, perm, the path or dir target, the action or the
// list twice is never decided on its last value. Through the full check it
// is ambiguous, whichever side repeats, and the same rule given once passes.
//
// Two cases are kernel counterexamples: the kernel requires every occurrence
// to match (from its rule semantics, not measured here), so -F arch=b32
// -F arch=b64 matches no event, and -F perm=w -F perm=wa records writes. The
// rest are conservative declines: the kernel is not shown to accept such a
// rule at all.
//
// @spec check-audit-rule-match
// @ac AC-24
func TestAuditRuleExists_RepeatedSpecialFieldIsAmbiguous(t *testing.T) {
	t.Run("check-audit-rule-match/AC-24", func(t *testing.T) {
		for _, c := range []struct{ name, kind, rule, loaded string }{
			{"arch", "kernel counterexample", "-a always,exit -F arch=b64 -S read -k k",
				"-a always,exit -F arch=b32 -F arch=b64 -S read -F key=k"},
			{"perm", "kernel counterexample", "-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=w -k k",
				"-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=w -F perm=wa -F key=k"},
			{"path", "conservative decline", "-a always,exit -F arch=b64 -S open -F path=/etc/shadow -k k",
				"-a always,exit -F arch=b64 -S open -F path=/etc/gshadow -F path=/etc/shadow -F key=k"},
			{"dir", "conservative decline", "-a always,exit -F arch=b64 -S open -F dir=/etc/sudoers.d -k k",
				"-a always,exit -F arch=b64 -S open -F dir=/var/tmp -F dir=/etc/sudoers.d -F key=k"},
			{"-w twice", "conservative decline", "-w /etc/shadow -p wa -k k",
				"-w /etc/gshadow -w /etc/shadow -p wa -k k"},
			{"-p twice", "conservative decline", "-w /etc/shadow -p wa -k k",
				"-w /etc/shadow -p r -p wa -k k"},
			{"-w with -F path", "conservative decline", "-w /etc/shadow -p wa -k k",
				"-w /etc/shadow -F path=/etc/gshadow -p wa -k k"},
			{"-p with -F perm", "conservative decline", "-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k k",
				"-a always,exit -F arch=b64 -S all -F path=/etc/shadow -p r -F perm=wa -F key=k"},
			{"action twice", "conservative decline", "-a always,exit -F arch=b64 -S read -k k",
				"-a never,always,exit -F arch=b64 -S read -F key=k"},
			{"list twice", "conservative decline", "-a always,exit -F arch=b64 -S read -k k",
				"-a always,task,exit -F arch=b64 -S read -F key=k"},
		} {
			for side, pair := range map[string][2]string{"loaded": {c.rule, c.loaded}, "requirement": {c.loaded, c.loaded}} {
				ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, pair[1])}}
				res, err := Run(context.Background(), ft, api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": pair[0]}})
				if res.Passed || (err != nil && !errors.Is(err, ErrAmbiguousEvidence)) {
					t.Errorf("%s (%s), repeat on the %s side: passed=%v err=%v", c.name, c.kind, side, res.Passed, err)
				}
				if p := parseAuditK(pair[1], auditLoaded); p.ok && !errors.Is(err, ErrAmbiguousEvidence) {
					t.Errorf("%s (%s), repeat on the %s side: err=%v, want ErrAmbiguousEvidence", c.name, c.kind, side, err)
				}
			}
			plain := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, c.rule)}}
			if res, err := Run(context.Background(), plain, api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": c.rule}}); !strings.HasPrefix(c.rule, "-w") && (err != nil || !res.Passed) {
				t.Errorf("%s: the rule loaded once: passed=%v err=%v", c.name, res.Passed, err)
			}
		}
		// A repeat decides nothing beyond its own field: an unrelated loaded
		// line with a repeat leaves a missing requirement a clean fail, so one
		// such line on a host does not turn every absent control into a skip.
		for _, c := range []struct{ name, rule, loaded string }{
			{"other syscall and key", "-a always,exit -F arch=b64 -S chmod -k perm_mod",
				"-a always,exit -F arch=b32 -F arch=b64 -S execve -F key=weird"},
			{"other path and key", "-w /etc/shadow -p wa -k identity",
				"-a always,exit -F arch=b64 -S all -F path=/var/log/x -F perm=w -F perm=wa -F key=weird"},
			{"a never rule", "-a always,exit -F arch=b64 -S read -k k",
				"-a never,exit -F arch=b32 -F arch=b64 -S read -F key=k"},
			{"another list", "-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k k",
				"-a always,exclude -F msgtype=CWD -F perm=w -F perm=wa"},
			{"a repeat on the requirement, another listed rule", "-a always,exit -F arch=b32 -F arch=b64 -S read -k k",
				"-a always,exit -F arch=b64 -S chmod -F key=other"},
		} {
			ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, c.loaded)}}
			res, err := Run(context.Background(), ft, api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": c.rule}})
			if err != nil || res.Passed {
				t.Errorf("%s: passed=%v err=%v, want a clean fail", c.name, res.Passed, err)
			}
		}
		// For identity a repeat is Unresolved, and a difference in another
		// field still makes two rules distinct.
		target := testAuditTarget()
		if id, _ := AuditRuleIdentity("-a always,exit -F arch=b32 -F arch=b64 -S read -k k", "-a always,exit -F arch=b64 -S read -k k", target); id != AuditUnresolved {
			t.Errorf("repeated arch vs the last value: %v, want Unresolved", id)
		}
		if id, _ := AuditRuleIdentity("-a always,exit -F arch=b32 -F arch=b64 -S read -k k", "-a always,exit -F arch=b64 -S read -k other", target); id != AuditDistinct {
			t.Errorf("repeated arch under another key: %v, want Distinct", id)
		}
	})
}

// OnlyNotAssessable is true when every part of an error is not assessable:
// a bare sentinel, one wrapped by fmt.Errorf, and a join of such errors. A
// join with any other error, and nil, is false.
//
// @spec scan-compliance-outcome
// @ac AC-11
func TestOnlyNotAssessable(t *testing.T) {
	t.Run("scan-compliance-outcome/AC-11", func(t *testing.T) {
		wrapped := fmt.Errorf("%w: detail", ErrAmbiguousEvidence)
		plain := errors.New("transport: connection reset")
		for name, c := range map[string]struct {
			err  error
			want bool
		}{
			"nil":                {nil, false},
			"sentinel":           {ErrNotAssessable, true},
			"wrapped":            {wrapped, true},
			"join of two":        {errors.Join(wrapped, fmt.Errorf("x: %w", ErrNotAssessable)), true},
			"wrapped join":       {fmt.Errorf("outer: %w", errors.Join(wrapped, wrapped)), true},
			"join with plain":    {errors.Join(wrapped, plain), false},
			"nested join, plain": {errors.Join(wrapped, errors.Join(wrapped, plain)), false},
			"plain":              {plain, false},
			"empty join":         {joinedError(nil), false},
		} {
			if got := OnlyNotAssessable(c.err); got != c.want {
				t.Errorf("%s: %v, want %v", name, got, c.want)
			}
		}
	})
}

// A multi check's joined error reads as one line, its parts separated by
// "; ", and errors.Is still finds each part.
//
// @spec scan-compliance-outcome
// @ac AC-11
func TestJoinedErrorIsOneLine(t *testing.T) {
	t.Run("scan-compliance-outcome/AC-11", func(t *testing.T) {
		err := joinedError{errors.New("a"), fmt.Errorf("b: %w", ErrAmbiguousEvidence)}
		if got := err.Error(); got != "a; b: "+ErrAmbiguousEvidence.Error() || strings.Contains(got, "\n") {
			t.Errorf("Error() = %q", got)
		}
		if !errors.Is(err, ErrAmbiguousEvidence) {
			t.Error("errors.Is does not find a joined part")
		}
	})
}
