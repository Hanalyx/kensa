package sysctlset

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the sysctl_set handler with the global registry.
func init() {
	handler.Register(New())
}
