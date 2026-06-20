// Package auditnl holds the agent-side AUDIT_NETLINK primitives: the
// audit_rule_set handler uses them to load/unload audit rules via the
// kernel's netlink interface (the auditctl mechanism) instead of shelling
// out to augenrules, and the engine uses EmitPhaseEvent to write
// transaction-phase records into auditd. Netlink AUDIT requires
// CAP_AUDIT_CONTROL (root); when the socket cannot be opened the
// primitives return ErrAuditUnavailable so callers fall back to the shell
// path — mirroring systemd.ErrHelperNotFound.
package auditnl

import (
	"errors"
	"fmt"
	"strings"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
)

// ErrAuditUnavailable is returned when the AUDIT netlink socket cannot be
// opened (no privilege, or audit not compiled in). A handler treats it as
// the signal to fall back to its shell path, exactly as the systemd
// handlers treat systemd.ErrHelperNotFound.
var ErrAuditUnavailable = errors.New("auditnl: audit netlink unavailable")

// AuditClient is the subset of the go-libaudit client the handler uses,
// defined as an interface so tests can inject an in-memory fake without a
// real netlink socket. *libaudit.AuditClient satisfies it.
type AuditClient interface {
	// AddRule loads a rule (in kernel wire format) into the kernel.
	AddRule(rule []byte) error
	// DeleteRule unloads a rule (in kernel wire format) from the kernel.
	DeleteRule(rule []byte) error
	// GetRules returns the currently-loaded rules in kernel wire format.
	GetRules() ([][]byte, error)
	// Close releases the netlink socket.
	Close() error
}

var _ AuditClient = (*libaudit.AuditClient)(nil)

// Open opens a real AUDIT netlink client. A failure to open (the common
// non-root / no-audit case) is wrapped as ErrAuditUnavailable so callers
// can branch to their shell fallback.
func Open() (AuditClient, error) {
	c, err := libaudit.NewAuditClient(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return c, nil
}

// BuildRule parses one auditctl-syntax rule line (e.g.
// "-w /etc/passwd -p wa -k identity" or
// "-a always,exit -F arch=b64 -S execve -k exec") and returns its kernel
// wire format, suitable for AddRule/DeleteRule and for byte-equality
// comparison against GetRules output. The go-libaudit parser is the same
// grammar auditctl implements, so we do not reimplement it.
func BuildRule(line string) ([]byte, error) {
	r, err := flags.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("auditnl: parse %q: %w", line, err)
	}
	wire, err := rule.Build(r)
	if err != nil {
		return nil, fmt.Errorf("auditnl: build %q: %w", line, err)
	}
	return []byte(wire), nil
}

// RuleLines splits a rule-set body into the individual audit-rule lines
// to load, dropping blank lines and comments (and the Kensa header). Each
// returned line is fed to BuildRule.
func RuleLines(body string) []string {
	var out []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
