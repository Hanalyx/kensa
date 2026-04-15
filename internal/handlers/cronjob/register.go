package cronjob

import "github.com/Hanalyx/kensa-go/internal/handler"

// init registers the cron_job handler with the global registry.
func init() {
	handler.Register(New())
}
