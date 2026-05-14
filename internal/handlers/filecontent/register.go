package filecontent

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the file_content handler with the global registry.
func init() {
	handler.Register(New())
}
