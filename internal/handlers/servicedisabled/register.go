package servicedisabled

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the service_disabled handler with the global registry.
func init() {
	handler.Register(New())
}
