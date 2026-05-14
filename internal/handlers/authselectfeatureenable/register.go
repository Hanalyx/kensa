package authselectfeatureenable

import "github.com/Hanalyx/kensa/internal/handler"

// init registers the authselect_feature_enable handler with the global registry.
func init() {
	handler.Register(New())
}
