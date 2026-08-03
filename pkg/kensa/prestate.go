package kensa

import (
	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/handler"
)

// DescribePreState renders a captured pre-state as one operator-readable
// line, so a consumer can show what a transaction found on the host before
// it changed anything:
//
//	before: PASS_MAX_DAYS 99999
//
// It works on any [api.PreState] — one from [api.TransactionResult],
// from [api.TransactionRecord] read back out of the log, or from
// [api.Plan] in a preview flow — and it derives the line on read, so it
// applies to pre-state captured by earlier versions of Kensa as well as to
// new transactions.
//
// The line comes from the handler that did the capturing, since only it
// knows what its own mechanism-specific [api.PreState.Data] keys mean. A
// mechanism with no describer falls back to a safe generic rendering of its
// field names. Handlers are registered by importing this package, so no
// further wiring is required.
//
// # This is a projection, not evidence
//
// [api.PreState.Data] remains the authoritative capture and the thing an
// auditor reads; the summary is for a screen. The rendered text carries no
// stability guarantee — it is not semver-frozen, not parseable, and may
// change in any release including a patch. A consumer that persists the
// summary rather than deriving it on read should record the Kensa version
// alongside it, so a corrected describer can be re-run over the rows it
// affects.
//
// # Disclosure
//
// Captured pre-state is kept verbatim so rollback can restore it, and it is
// not scrubbed. A summary is shown inline where raw Data usually is not, so it
// is elided by construction. What that does and does not guarantee, stated
// precisely because an earlier version of this comment overstated it:
//
//   - No describer and no fallback emits a captured FILE BODY, at any length.
//     Values are rendered through helpers that replace anything multi-line or
//     over the inline limit with a size marker.
//   - Data field names denoting credentials are redacted in the generic
//     fallback, by the same name-based rule the evidence sanitizer uses.
//   - Configuration LINES rendered by config_set and mount_option_set are
//     additionally scanned for a credential-bearing key inside the line, since
//     the sensitive name there belongs to the host's config file rather than
//     to the Data key holding it.
//
// It is not a secret scanner. A credential in an unexpected shape, or under a
// key that names nothing, can still reach a summary. Treat the output as
// operator-visible text.
//
// A non-capturable step returns a fixed marker rather than an empty string,
// so a caller can render the distinction between "nothing was captured
// because this mechanism cannot capture" and "no summary available".
func DescribePreState(pre api.PreState) string {
	return handler.DescribePreState(&pre)
}
