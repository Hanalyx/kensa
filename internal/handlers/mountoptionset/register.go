package mountoptionset

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the mount_option_set handler with the global registry.
func init() {
	handler.Register(New())
}
