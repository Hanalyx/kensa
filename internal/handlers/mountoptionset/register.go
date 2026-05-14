package mountoptionset

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the mount_option_set handler with the global registry.
func init() {
	handler.Register(New())
}
