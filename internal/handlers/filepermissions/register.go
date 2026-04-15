package filepermissions

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the file_permissions handler with the global
// registry. Imported into the engine startup path so the registration
// fires before any rule references the mechanism.
func init() {
	handler.Register(New())
}
