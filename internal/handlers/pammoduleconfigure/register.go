package pammoduleconfigure

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the pam_module_configure handler with the global
// registry.
func init() {
	handler.Register(New())
}
