package sysctlset

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the sysctl_set handler with the global registry.
func init() {
	handler.Register(New())
}
