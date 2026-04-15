package configappend

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the config_append handler with the global registry.
func init() {
	handler.Register(New())
}
