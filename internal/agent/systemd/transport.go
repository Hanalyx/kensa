package systemd

import "context"

// Transport is the capability interface a transport implements when it
// can drive systemd through the privileged D-Bus helper — i.e. when the
// handler is running inside the agent on the target host. It mirrors the
// fsatomic.Transport pattern: a handler type-asserts
// transport.(systemd.Transport); when the assertion succeeds it uses the
// D-Bus path, and when it fails (the SSH shell transport does not
// implement this) it falls back to `systemctl` shell-out.
//
// The methods are the subset of Client the service handlers need across
// Apply/Capture/Rollback. Each returns the typed *Response so a caller
// can read SettledState (post-condition) and UnitState (Capture), and
// distinguish a structured HelperError from a transport/exec failure.
type Transport interface {
	Enable(ctx context.Context, unit string) (*Response, error)
	Disable(ctx context.Context, unit string) (*Response, error)
	Mask(ctx context.Context, unit string) (*Response, error)
	Unmask(ctx context.Context, unit string) (*Response, error)
	Start(ctx context.Context, unit string) (*Response, error)
	Stop(ctx context.Context, unit string) (*Response, error)
	UnitState(ctx context.Context, unit string) (*Response, error)
}

// Client satisfies Transport — the local (agent) transport embeds a
// *Client and is therefore the production implementation. The assertion
// is here (not in the transport package) so a change to this interface
// fails to compile against Client at the source of truth.
var _ Transport = (*Client)(nil)
