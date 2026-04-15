package selinuxbooleanset

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the selinux_boolean_set handler with the global registry.
func init() {
	handler.Register(New())
}
