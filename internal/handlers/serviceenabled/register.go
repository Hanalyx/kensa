package serviceenabled

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the service_enabled handler with the global registry.
func init() {
	handler.Register(New())
}
