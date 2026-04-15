package dconfset

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the dconf_set handler with the global registry.
func init() {
	handler.Register(New())
}
