package ssh

import (
	"context"

	"github.com/Hanalyx/kensa-go/api"
)

// Factory satisfies [api.TransportFactory] by constructing a
// [Transport] from a [api.HostConfig] via [Connect]. Use this when
// wiring an [api.Kensa] that needs to open SSH connections from
// caller-supplied host descriptions.
type Factory struct{}

// Connect translates host into a ssh [Config] and returns the
// resulting [Transport]. The returned transport is owned by the
// caller; close it with [Transport.Close].
func (Factory) Connect(ctx context.Context, host api.HostConfig) (api.Transport, error) {
	cfg := Config{
		Host:     host.Hostname,
		User:     host.User,
		Port:     host.Port,
		Sudo:     host.Sudo,
		KeyPath:  host.KeyPath,
		Password: host.Password,
	}
	return Connect(ctx, cfg)
}

// Compile-time assertion: Factory satisfies [api.TransportFactory].
var _ api.TransportFactory = Factory{}
