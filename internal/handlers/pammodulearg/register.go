package pammodulearg

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the pam_module_arg handler with the global registry.
func init() {
	handler.Register(New())
}
