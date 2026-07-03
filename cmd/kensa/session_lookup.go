package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// cleanSessionLookupError converts a store GetSession error into an
// operator-actionable CLI message. A missing session (sql.ErrNoRows, or the
// wrapped "no rows in result set" text) becomes a "not found in store" message
// carrying a command-specific discovery hint; any other error is wrapped with
// the session id.
//
// This is the single home for the C-047/C-048 ErrNotFound contract, shared by
// `kensa diff` and the session-aware rollback path. Previously each command
// kept its own near-identical copy (cleanSessionLookupError /
// cleanRollbackSessionLookupError) that drifted one bug at a time; the only
// legitimate difference is the discovery hint, which is now a parameter.
//
// hint is the caller's discovery suggestion, e.g.
// "try 'kensa list sessions' to find candidate IDs".
func cleanSessionLookupError(id uuid.UUID, err error, hint string) error {
	if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no rows") {
		return fmt.Errorf("session %s not found in store (%s)", id, hint)
	}
	return fmt.Errorf("session %s: %w", id, err)
}
