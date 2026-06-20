package auditnl

import (
	"fmt"
	"syscall"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

// Emitter writes Kensa transaction-phase records into the local auditd via
// an AUDIT_USER (type 1005) netlink message — the observability the FedRAMP
// reviewer flagged: every transaction phase produces an event in the
// host's audit log, not just in Kensa's own evidence file. It holds one
// netlink socket for its lifetime.
//
// The engine runs on the controller, so events land in the controller
// (operator) host's auditd — the host kensa's actions originate from.
// Opening the socket needs CAP_AUDIT_WRITE (root); when it can't be opened
// the Emitter degrades to a silent no-op (client == nil) so emission is
// always safe to call and NEVER affects a transaction outcome.
type Emitter struct {
	client *libaudit.AuditClient
}

// NewEmitter opens an AUDIT netlink socket for emitting user records. It
// NEVER returns an error: on failure (no privilege / no audit) it returns
// a no-op Emitter, so the engine can always hold a usable, non-nil emitter
// and emission can never fail a transaction.
func NewEmitter() *Emitter {
	c, err := libaudit.NewAuditClient(nil)
	if err != nil {
		return &Emitter{}
	}
	return &Emitter{client: c}
}

// EmitPhase writes one transaction-phase record. Best-effort and
// non-blocking: it uses SendNoWait (no ACK wait) and swallows every error,
// so a slow or unavailable audit subsystem can never delay or fail a
// transaction. A no-op when the socket could not be opened.
func (e *Emitter) EmitPhase(txnID, phase string, ok bool) {
	if e == nil || e.client == nil {
		return
	}
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(auparse.AUDIT_USER),
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		},
		Data: []byte(formatPhaseMessage(txnID, phase, ok)),
	}
	_, _ = e.client.Netlink.SendNoWait(msg)
}

// Close releases the netlink socket. Safe on a no-op emitter.
func (e *Emitter) Close() error {
	if e == nil || e.client == nil {
		return nil
	}
	return e.client.Close()
}

// formatPhaseMessage renders the audit record body as auditd-style
// key=value text. Pure (no IO) so it is unit-testable without a socket.
func formatPhaseMessage(txnID, phase string, ok bool) string {
	result := "fail"
	if ok {
		result = "ok"
	}
	return fmt.Sprintf("op=kensa_transaction phase=%s txn=%s result=%s", phase, txnID, result)
}
