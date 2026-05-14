package configsetdropin

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the config_set_dropin handler with the global registry.
func init() {
	handler.Register(New())
}
