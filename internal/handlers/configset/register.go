package configset

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the config_set handler with the global registry.
func init() {
	handler.Register(New())
}
