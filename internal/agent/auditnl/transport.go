package auditnl

import "github.com/Hanalyx/kensa/internal/agent/kernelio"

// AuditTransport is the capability a transport implements when it can
// manage audit rules via AUDIT netlink: the FileTransport ops for the
// /etc/audit/rules.d drop-in persistence, plus AuditClient() to open a
// netlink client for the runtime rule load/unload. The audit_rule_set
// handler asserts it; AuditClient() returning ErrAuditUnavailable (or the
// assertion failing) sends the handler to its augenrules shell path.
type AuditTransport interface {
	kernelio.FileTransport
	// AuditClient opens a netlink client; the caller closes it. Returns a
	// wrapped ErrAuditUnavailable when the socket cannot be opened.
	AuditClient() (AuditClient, error)
}
