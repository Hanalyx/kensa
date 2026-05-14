package selinuxbooleanset

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the selinux_boolean_set handler with the global registry.
func init() {
	handler.Register(New())
}
