package fileabsent

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the file_absent handler with the global registry.
func init() {
	handler.Register(New())
}
