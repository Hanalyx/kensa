package aptpresent

import "github.com/Hanalyx/kensa-go/internal/handler"

func init() {
	handler.Default().Register(New())
}
