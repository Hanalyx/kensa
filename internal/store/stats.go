package store

import (
	"context"
	"fmt"
	"time"
)

// Stats is the aggregate summary returned by ComputeStats.
// Mirrors what `kensa history --stats` renders to the
// operator. Counts are computed against the full transactions
// table (and sessions table) — apply the StatsFilter to scope
// to a host or time window.
type Stats struct {
	// SessionsTotal is the count of distinct sessions in the
	// store after the filter applies. Pre-Phase-4 transactions
	// without a session (NULL session_id) contribute zero
	// sessions; their transactions still appear in
	// TransactionsTotal etc.
	SessionsTotal int `json:"sessions_total"`

	// TransactionsTotal is the count of transactions matching
	// the filter.
	TransactionsTotal int `json:"transactions_total"`

	// ByStatus is the per-status breakdown ("committed",
	// "rolled_back", "partially_applied", "errored"). Keys
	// without rows are omitted.
	ByStatus map[string]int `json:"by_status"`

	// BySeverity is the per-severity breakdown ("critical",
	// "high", "medium", "low"). Empty severity (legacy or
	// unset) is keyed as "(unset)".
	BySeverity map[string]int `json:"by_severity"`

	// ByHost is the per-host transaction count. The top
	// TopHostsLimit hosts are returned; the rest are summed
	// into the "(other)" key. Set TopHostsLimit=0 in the
	// caller's filter for "all hosts no rollup" behavior.
	ByHost map[string]int `json:"by_host"`

	// EarliestStartedAt and LatestFinishedAt span the time
	// window covered by the matching transactions. Zero values
	// when no transactions match the filter.
	EarliestStartedAt time.Time `json:"earliest_started_at"`
	LatestFinishedAt  time.Time `json:"latest_finished_at"`
}

// StatsFilter scopes ComputeStats. Empty fields mean "no
// constraint." The filter applies to transactions; the
// SessionsTotal count is computed from the same scope (sessions
// whose hostname / time window matches).
type StatsFilter struct {
	Host  string
	Since time.Time // inclusive lower bound; zero = no lower bound
	// TopHostsLimit caps ByHost map cardinality. Hosts beyond
	// the limit are summed into "(other)". Zero = no rollup.
	TopHostsLimit int
}

// ComputeStats runs the aggregation. Returns a fully-populated
// Stats even on an empty store (zero counts, nil/empty maps,
// zero timestamps).
func (s *SQLite) ComputeStats(ctx context.Context, filter StatsFilter) (*Stats, error) {
	out := &Stats{
		ByStatus:   map[string]int{},
		BySeverity: map[string]int{},
		ByHost:     map[string]int{},
	}

	// Build the WHERE clause shared by transactions queries.
	where := "WHERE 1=1"
	args := []any{}
	if filter.Host != "" {
		where += " AND host_id = ?"
		args = append(args, filter.Host)
	}
	if !filter.Since.IsZero() {
		where += " AND started_at >= ?"
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}

	// Total transactions + time bounds in one round-trip.
	var earliest, latest *string
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*), MIN(started_at), MAX(finished_at) FROM transactions "+where,
		args...,
	).Scan(&out.TransactionsTotal, &earliest, &latest); err != nil {
		return nil, fmt.Errorf("stats: total: %w", err)
	}
	if earliest != nil {
		t, err := time.Parse(time.RFC3339Nano, *earliest)
		if err == nil {
			out.EarliestStartedAt = t
		}
	}
	if latest != nil {
		t, err := time.Parse(time.RFC3339Nano, *latest)
		if err == nil {
			out.LatestFinishedAt = t
		}
	}

	// Sessions total — scope by the same host/since filter as
	// transactions for consistency. A pre-Phase-4 row's parent
	// session is counted only after C-040 backfill runs.
	sessWhere := "WHERE 1=1"
	sessArgs := []any{}
	if filter.Host != "" {
		sessWhere += " AND hostname = ?"
		sessArgs = append(sessArgs, filter.Host)
	}
	if !filter.Since.IsZero() {
		sessWhere += " AND started_at >= ?"
		sessArgs = append(sessArgs, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sessions "+sessWhere,
		sessArgs...,
	).Scan(&out.SessionsTotal); err != nil {
		return nil, fmt.Errorf("stats: sessions: %w", err)
	}

	// By-status / by-severity / by-host. Three GROUP BY
	// queries; could collapse into one with conditional sums
	// but the row-shape would be denser than worth it.
	if err := scanGroupCounts(ctx, s, "status", where, args, out.ByStatus); err != nil {
		return nil, err
	}
	if err := scanGroupCounts(ctx, s, "severity", where, args, out.BySeverity); err != nil {
		return nil, err
	}
	if err := scanGroupCounts(ctx, s, "host_id", where, args, out.ByHost); err != nil {
		return nil, err
	}

	// Apply ByHost top-N rollup if requested.
	if filter.TopHostsLimit > 0 && len(out.ByHost) > filter.TopHostsLimit {
		out.ByHost = rollupTopN(out.ByHost, filter.TopHostsLimit)
	}

	// Normalize legacy/empty severity rows to "(unset)" so the
	// operator-facing output isn't a confusing blank key.
	if n, ok := out.BySeverity[""]; ok {
		delete(out.BySeverity, "")
		if n > 0 {
			out.BySeverity["(unset)"] = n
		}
	}

	return out, nil
}

// scanGroupCounts runs a SELECT group_col, COUNT(*) and writes
// the result into dst.
func scanGroupCounts(ctx context.Context, s *SQLite, groupCol, where string, args []any, dst map[string]int) error {
	q := fmt.Sprintf(
		"SELECT %s, COUNT(*) FROM transactions %s GROUP BY %s",
		groupCol, where, groupCol,
	)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("stats: group by %s: %w", groupCol, err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return fmt.Errorf("stats: scan group %s: %w", groupCol, err)
		}
		dst[key] = count
	}
	return rows.Err()
}

// rollupTopN keeps the highest-count `n` keys verbatim and
// sums the rest into "(other)". Used by ComputeStats to bound
// ByHost cardinality on large fleets.
func rollupTopN(in map[string]int, n int) map[string]int {
	if n <= 0 || len(in) <= n {
		return in
	}
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(in))
	for k, v := range in {
		pairs = append(pairs, kv{k, v})
	}
	// Insertion sort would be fine for typical small N; using
	// a simple O(N^2) selection-style top-N to avoid pulling
	// in sort.Slice's closure overhead and to keep the order
	// deterministic when ties occur (alphabetical key wins).
	out := make(map[string]int, n+1)
	taken := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		bestIdx := -1
		for j, p := range pairs {
			if taken[p.k] {
				continue
			}
			if bestIdx == -1 ||
				p.v > pairs[bestIdx].v ||
				(p.v == pairs[bestIdx].v && p.k < pairs[bestIdx].k) {
				bestIdx = j
			}
		}
		if bestIdx == -1 {
			break
		}
		out[pairs[bestIdx].k] = pairs[bestIdx].v
		taken[pairs[bestIdx].k] = true
	}
	other := 0
	for _, p := range pairs {
		if !taken[p.k] {
			other += p.v
		}
	}
	if other > 0 {
		out["(other)"] = other
	}
	return out
}
