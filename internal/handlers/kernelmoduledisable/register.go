package kernelmoduledisable

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the kernel_module_disable handler with the global registry.
func init() {
	handler.Register(New())
}
