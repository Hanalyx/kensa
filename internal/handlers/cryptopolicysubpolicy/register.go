package cryptopolicysubpolicy

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the crypto_policy_subpolicy handler with the global registry.
func init() {
	handler.Register(New())
}
