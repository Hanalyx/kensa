package cryptopolicyset

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the crypto_policy_set handler with the global registry.
func init() {
	handler.Register(New())
}
