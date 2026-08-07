package ssh

import (
	"context"

	"github.com/Hanalyx/kensa/api"
)

// Factory satisfies [api.TransportFactory] by constructing a
// [Transport] from a [api.HostConfig] via [Connect]. Use this when
// wiring an [api.Kensa] that needs to open SSH connections from
// caller-supplied host descriptions.
type Factory struct {
	// SocketTag is passed through to [Config.SocketTag], giving this
	// factory's transports a private ControlMaster socket. The zero value
	// keeps the shared socket, so existing callers are unaffected.
	SocketTag string
}

// Connect translates host into a ssh [Config] and returns the
// resulting [Transport]. The returned transport is owned by the
// caller; close it with [Transport.Close].
func (f Factory) Connect(ctx context.Context, host api.HostConfig) (api.Transport, error) {
	cfg := Config{
		Host:           host.Hostname,
		User:           host.User,
		Port:           host.Port,
		Sudo:           host.Sudo,
		SudoPassword:   host.SudoPassword,
		KeyPath:        host.KeyPath,
		Password:       host.Password,
		StrictHostKeys: host.StrictHostKeys,
		SocketTag:      f.SocketTag,
	}
	return Connect(ctx, cfg)
}

// Compile-time assertion: Factory satisfies [api.TransportFactory].
var _ api.TransportFactory = Factory{}
