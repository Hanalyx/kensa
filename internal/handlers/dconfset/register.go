package dconfset

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the dconf_set handler with the global registry.
func init() {
	handler.Register(New())
}
