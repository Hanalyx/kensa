package aptpresent

import "github.com/Hanalyx/kensa/internal/handler"

func init() {
	handler.Default().Register(New())
}
