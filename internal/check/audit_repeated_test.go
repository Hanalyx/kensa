package check

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Hanalyx/kensa/api"
)

// The kernel ANDs every field, so a loaded rule that repeats arch, perm,
// path or dir matches only events that satisfy both. The parser keeps one
// value of each, so a repeat must not let the check pass a requirement the
// second value would decide: the full check does not pass.
//
// @spec check-audit-rule-match
// @ac AC-24
func TestAuditRuleExists_RepeatedSpecialFieldDoesNotPass(t *testing.T) {
	t.Run("check-audit-rule-match/AC-24", func(t *testing.T) {
		for _, c := range []struct{ name, rule, loaded string }{
			{"arch", "-a always,exit -F arch=b64 -S read -k k",
				"-a always,exit -F arch=b32 -F arch=b64 -S read -F key=k"},
			{"perm", "-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k k",
				"-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=x -F perm=wa -F key=k"},
			{"path", "-a always,exit -F arch=b64 -S open -F path=/etc/shadow -k k",
				"-a always,exit -F arch=b64 -S open -F path=/etc/gshadow -F path=/etc/shadow -F key=k"},
			{"dir", "-a always,exit -F arch=b64 -S open -F dir=/etc/sudoers.d -k k",
				"-a always,exit -F arch=b64 -S open -F dir=/var/tmp -F dir=/etc/sudoers.d -F key=k"},
		} {
			ft := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, c.loaded)}}
			res, err := Run(context.Background(), ft, api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": c.rule}})
			if err == nil && res.Passed {
				t.Errorf("%s: a loaded rule with a repeated %s field passed %q", c.name, c.name, c.rule)
			}
			// The same rule without the repeat still passes.
			plain := &fakeTransport{cmdResult: map[string]api.CommandResult{"auditctl -l": result(0, c.rule)}}
			if res, err := Run(context.Background(), plain, api.Check{Method: "audit_rule_exists", Params: api.Params{"rule": c.rule}}); err != nil || !res.Passed {
				t.Errorf("%s: the rule loaded once: passed=%v err=%v", c.name, res.Passed, err)
			}
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
		} {
			if got := OnlyNotAssessable(c.err); got != c.want {
				t.Errorf("%s: %v, want %v", name, got, c.want)
			}
		}
	})
}
