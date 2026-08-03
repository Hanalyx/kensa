package handler

import (
	"strings"

	"github.com/Hanalyx/kensa/api"
	"github.com/Hanalyx/kensa/internal/prestate"
)

// PreStateDescriber is the optional interface a capturable handler
// implements to render its own captured pre-state as one operator-readable
// line. It follows the same runtime-assertion pattern as
// [api.CaptureHandler] and [api.RollbackHandler]: a handler that does not
// implement it still satisfies [api.Handler], and callers reach it only
// through [Registry.DescribePreState].
//
// The describer lives with the handler, next to its Capture, because only
// the handler knows what its own Data keys mean. That adjacency is the
// point: a change to the captured layout and a change to its summary land
// in the same diff, so the two cannot drift the way an external decoder
// would.
//
// Two obligations on an implementation:
//
//   - Be total. Data may come from a live capture, from the agent wire
//     format (integers widened to int64), from a JSON round-trip through
//     the transaction log (numbers as float64), or from an older Kensa that
//     recorded different keys. Use the internal/prestate accessors rather
//     than type-asserting, and never assume a key is present.
//   - Emit no captured file body. Render content through
//     [prestate.Text] or report its size with [prestate.Size]. A summary is
//     shown inline where raw Data is not, so it is a wider disclosure
//     surface than the capture it describes.
//
// Returning the empty string is allowed and means "no better line than the
// generic one"; the caller falls back to [prestate.Generic].
type PreStateDescriber interface {
	DescribePreState(pre *api.PreState) string
}

// DescribePreState renders pre as one operator-readable line, using the
// registered handler's own describer when it has one and a safe generic
// rendering otherwise.
//
// The result is a projection for display. It is not evidence, it is not a
// stable format, and it is not parseable — see the internal/prestate
// package documentation.
//
// A panic inside a describer is recovered and degrades to the generic
// rendering. This is a display path called over arbitrary historical
// pre-state, including records written by earlier versions of Kensa; a bad
// summary must not take down a caller that is merely rendering a page.
// Totality is still the describer's obligation and is tested per handler —
// the recovery is the backstop, not the contract.
func (r *Registry) DescribePreState(pre *api.PreState) (summary string) {
	if pre == nil {
		return ""
	}
	if !pre.Capturable {
		return "no pre-state (mechanism is not capturable)"
	}
	h, ok := r.Get(pre.Mechanism)
	if !ok {
		return prestate.Generic(pre)
	}
	d, ok := h.(PreStateDescriber)
	if !ok {
		return prestate.Generic(pre)
	}
	defer func() {
		if recover() != nil {
			summary = prestate.Generic(pre)
		}
	}()
	if s := strings.TrimSpace(d.DescribePreState(pre)); s != "" {
		return prestate.Truncate(s)
	}
	return prestate.Generic(pre)
}

// DescribePreState renders pre against the global registry. See
// [Registry.DescribePreState].
func DescribePreState(pre *api.PreState) string {
	return Default().DescribePreState(pre)
}
