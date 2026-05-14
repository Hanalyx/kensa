package packagepresent

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the package_present handler with the global registry.
func init() {
	handler.Register(New())
}
