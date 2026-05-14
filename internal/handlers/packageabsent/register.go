package packageabsent

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the package_absent handler with the global registry.
func init() {
	handler.Register(New())
}
