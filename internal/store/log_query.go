package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Hanalyx/kensa/api"
)

// Query implements [api.LogQuery.Query] against the SQLite backend.
// Builds a parameterized WHERE clause from the provided [api.LogFilter]
// and returns paginated results.
func (s *SQLite) Query(ctx context.Context, filter api.LogFilter, page api.Page) (*api.QueryResult, error) {
	where, args := buildWhereClause(filter)
	limit := page.Limit
	if limit <= 0 {
		limit = 100
	}

	// Total count for pagination metadata.
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM transactions `+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("store: count: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, rule_id, host_id, fleet_id, status, transactional, severity,
                started_at, finished_at
         FROM transactions `+where+
			` ORDER BY started_at DESC LIMIT ? OFFSET ?`,
		append(args, limit, page.Offset)...)
	if err != nil {
		return nil, fmt.Errorf("store: query: %w", err)
	}
	defer rows.Close()

	out := &api.QueryResult{Total: total, Offset: page.Offset, Limit: limit}
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out.Transactions = append(out.Transactions, *rec)
	}
	return out, rows.Err()
}

// Get implements [api.LogQuery.Get]. Default returns full record
// including envelope and pre-states; opts may opt out for performance.
func (s *SQLite) Get(ctx context.Context, txnID uuid.UUID, opts ...api.GetOption) (*api.TransactionRecord, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, rule_id, host_id, fleet_id, status, transactional, severity,
               started_at, finished_at, envelope_json
        FROM transactions WHERE id = ?`, txnID.String())

	var (
		idStr, ruleID, hostID, fleetID, status, severity string
		transactional                                    int
		startedAt, finishedAt                            string
		envJSON                                          string
	)
	if err := row.Scan(&idStr, &ruleID, &hostID, &fleetID, &status, &transactional, &severity,
		&startedAt, &finishedAt, &envJSON); err != nil {
		return nil, fmt.Errorf("store: get %s: %w", txnID, err)
	}

	rec := &api.TransactionRecord{
		ID:            txnID,
		RuleID:        ruleID,
		HostID:        hostID,
		FleetID:       fleetID,
		Status:        api.TransactionStatus(status),
		Transactional: transactional != 0,
		Severity:      severity,
	}
	rec.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
	rec.FinishedAt, _ = time.Parse(time.RFC3339Nano, finishedAt)

	includeEnv, includePre := applyGetOptions(opts)
	if includeEnv {
		var env api.EvidenceEnvelope
		if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
			return nil, fmt.Errorf("store: unmarshal envelope for %s: %w", txnID, err)
		}
		rec.Envelope = &env
		// Populate rec.Steps from envelope.ApplySteps. Pre-this
		// line, rec.Steps was always nil after a Get(), so the
		// manual-rollback CLI path
		// (engine.RollbackTransaction reads record.Steps to
		// know what to reverse) executed an empty step list
		// and produced a synthetic
		// "all rollback steps succeeded" response while host
		// state stayed unchanged — a silent atomicity-contract
		// violation surfaced by the 2026-05-13 live test on
		// 192.168.1.211. Steps are persisted into both the
		// normalized `steps` table (for filterable queries)
		// and the envelope_json blob (signed audit truth);
		// the envelope is already in memory here, so reading
		// it costs nothing and avoids a second SELECT.
		rec.Steps = env.ApplySteps
	}
	if includePre {
		preStates, err := s.LoadPreStates(ctx, txnID)
		if err != nil {
			return nil, err
		}
		rec.PreStates = preStates
	}
	return rec, nil
}

// Aggregate implements [api.LogQuery.Aggregate].
func (s *SQLite) Aggregate(ctx context.Context, filter api.LogFilter, groupBy api.AggregateKey, opts ...api.AggregateOption) (*api.AggregateResult, error) {
	where, args := buildWhereClause(filter)
	out := &api.AggregateResult{GroupBy: groupBy}

	switch groupBy {
	case api.AggregateByHost:
		return s.aggregateByColumn(ctx, "host_id", where, args, out)
	case api.AggregateByRule:
		return s.aggregateByColumn(ctx, "rule_id", where, args, out)
	case api.AggregateByFrameworkControl:
		return s.aggregateByFrameworkControl(ctx, where, args, out)
	case api.AggregateByHostThenFrameworkControl:
		return s.aggregateByHostThenFrameworkControl(ctx, where, args, out)
	case api.AggregateByRuleThenStatusOverTime:
		bucket := applyAggregateOptions(opts)
		if bucket == "" {
			return nil, fmt.Errorf("store: AggregateByRuleThenStatusOverTime requires WithTimeBucket")
		}
		out.TimeBucket = bucket
		return s.aggregateByRuleOverTime(ctx, where, args, bucket, out)
	default:
		return nil, fmt.Errorf("store: unknown AggregateKey %q", groupBy)
	}
}

// aggregateByColumn groups transactions by the given column and emits
// status counts per group. Used by AggregateByHost and AggregateByRule.
func (s *SQLite) aggregateByColumn(ctx context.Context, column, where string, args []interface{}, out *api.AggregateResult) (*api.AggregateResult, error) {
	q := `SELECT ` + column + `, status, COUNT(*) FROM transactions ` + where +
		` GROUP BY ` + column + `, status ORDER BY ` + column
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: aggregate by %s: %w", column, err)
	}
	defer rows.Close()

	rowMap := make(map[string]*api.AggregateRow)
	for rows.Next() {
		var (
			key    string
			status string
			count  int
		)
		if err := rows.Scan(&key, &status, &count); err != nil {
			return nil, err
		}
		row, ok := rowMap[key]
		if !ok {
			row = &api.AggregateRow{StatusCounts: make(map[api.TransactionStatus]int)}
			switch column {
			case "host_id":
				row.HostID = key
			case "rule_id":
				row.RuleID = key
			}
			rowMap[key] = row
		}
		row.StatusCounts[api.TransactionStatus(status)] = count
		row.TotalCount += count
	}
	for _, row := range rowMap {
		out.Rows = append(out.Rows, *row)
	}
	return out, nil
}

// aggregateByFrameworkControl joins transactions to framework_refs.
func (s *SQLite) aggregateByFrameworkControl(ctx context.Context, where string, args []interface{}, out *api.AggregateResult) (*api.AggregateResult, error) {
	q := `SELECT framework_refs.framework_id, framework_refs.control_id,
                 transactions.status, COUNT(*)
          FROM transactions
          JOIN framework_refs ON framework_refs.transaction_id = transactions.id ` + where +
		` GROUP BY framework_refs.framework_id, framework_refs.control_id, transactions.status`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: aggregate by framework_control: %w", err)
	}
	defer rows.Close()

	type key struct{ fid, cid string }
	rowMap := make(map[key]*api.AggregateRow)
	for rows.Next() {
		var (
			fid, cid, status string
			count            int
		)
		if err := rows.Scan(&fid, &cid, &status, &count); err != nil {
			return nil, err
		}
		k := key{fid, cid}
		row, ok := rowMap[k]
		if !ok {
			row = &api.AggregateRow{
				FrameworkRef: &api.FrameworkRef{FrameworkID: fid, ControlID: cid},
				StatusCounts: make(map[api.TransactionStatus]int),
			}
			rowMap[k] = row
		}
		row.StatusCounts[api.TransactionStatus(status)] = count
		row.TotalCount += count
	}
	for _, row := range rowMap {
		out.Rows = append(out.Rows, *row)
	}
	return out, nil
}

// aggregateByHostThenFrameworkControl is the two-level grouping that
// the compliance-officer view consumes.
func (s *SQLite) aggregateByHostThenFrameworkControl(ctx context.Context, where string, args []interface{}, out *api.AggregateResult) (*api.AggregateResult, error) {
	q := `SELECT transactions.host_id,
                 framework_refs.framework_id, framework_refs.control_id,
                 transactions.status, COUNT(*)
          FROM transactions
          JOIN framework_refs ON framework_refs.transaction_id = transactions.id ` + where +
		` GROUP BY transactions.host_id, framework_refs.framework_id,
                 framework_refs.control_id, transactions.status`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: aggregate by host_then_framework_control: %w", err)
	}
	defer rows.Close()

	type key struct{ host, fid, cid string }
	rowMap := make(map[key]*api.AggregateRow)
	for rows.Next() {
		var (
			host, fid, cid, status string
			count                  int
		)
		if err := rows.Scan(&host, &fid, &cid, &status, &count); err != nil {
			return nil, err
		}
		k := key{host, fid, cid}
		row, ok := rowMap[k]
		if !ok {
			row = &api.AggregateRow{
				HostID:       host,
				FrameworkRef: &api.FrameworkRef{FrameworkID: fid, ControlID: cid},
				StatusCounts: make(map[api.TransactionStatus]int),
			}
			rowMap[k] = row
		}
		row.StatusCounts[api.TransactionStatus(status)] = count
		row.TotalCount += count
	}
	for _, row := range rowMap {
		out.Rows = append(out.Rows, *row)
	}
	return out, nil
}

// aggregateByRuleOverTime emits time-bucketed status counts per rule.
// SQLite's strftime handles the bucketing.
func (s *SQLite) aggregateByRuleOverTime(ctx context.Context, where string, args []interface{}, bucket api.TimeBucket, out *api.AggregateResult) (*api.AggregateResult, error) {
	var fmtStr string
	switch bucket {
	case api.HourBucket:
		fmtStr = "%Y-%m-%dT%H:00:00Z"
	case api.DayBucket:
		fmtStr = "%Y-%m-%d"
	case api.WeekBucket:
		fmtStr = "%Y-W%W"
	default:
		return nil, fmt.Errorf("store: unsupported TimeBucket %q", bucket)
	}

	q := `SELECT rule_id, strftime(?, started_at), status, COUNT(*)
          FROM transactions ` + where +
		` GROUP BY rule_id, strftime(?, started_at), status`
	queryArgs := append([]interface{}{fmtStr}, args...)
	queryArgs = append(queryArgs, fmtStr)
	rows, err := s.db.QueryContext(ctx, q, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("store: aggregate by rule_then_status_over_time: %w", err)
	}
	defer rows.Close()

	type key struct{ rule, bucket string }
	rowMap := make(map[key]*api.AggregateRow)
	for rows.Next() {
		var (
			rule, bucketKey, status string
			count                   int
		)
		if err := rows.Scan(&rule, &bucketKey, &status, &count); err != nil {
			return nil, err
		}
		k := key{rule, bucketKey}
		row, ok := rowMap[k]
		if !ok {
			row = &api.AggregateRow{
				RuleID:       rule,
				StatusCounts: make(map[api.TransactionStatus]int),
			}
			// Best-effort parse of the bucket key back to a time.
			if t, err := time.Parse(time.RFC3339, bucketKey); err == nil {
				row.TimeBucket = &t
			}
			rowMap[k] = row
		}
		row.StatusCounts[api.TransactionStatus(status)] = count
		row.TotalCount += count
	}
	for _, row := range rowMap {
		out.Rows = append(out.Rows, *row)
	}
	return out, nil
}

// scanRecord scans a row from the transactions list query into a
// summary [api.TransactionRecord]. Envelope and pre-states are not
// populated; callers needing them go through [SQLite.Get].
func scanRecord(scanner interface {
	Scan(dest ...interface{}) error
}) (*api.TransactionRecord, error) {
	var (
		idStr, ruleID, hostID, fleetID, status, severity string
		transactional                                    int
		startedAt, finishedAt                            string
	)
	if err := scanner.Scan(&idStr, &ruleID, &hostID, &fleetID, &status, &transactional, &severity,
		&startedAt, &finishedAt); err != nil {
		return nil, err
	}
	id, _ := uuid.Parse(idStr)
	rec := &api.TransactionRecord{
		ID:            id,
		RuleID:        ruleID,
		HostID:        hostID,
		FleetID:       fleetID,
		Status:        api.TransactionStatus(status),
		Transactional: transactional != 0,
		Severity:      severity,
	}
	rec.StartedAt, _ = time.Parse(time.RFC3339Nano, startedAt)
	rec.FinishedAt, _ = time.Parse(time.RFC3339Nano, finishedAt)
	return rec, nil
}

// buildWhereClause assembles a parameterized WHERE clause from filter.
// Returns the clause (including the WHERE keyword) and the slice of
// positional arguments.
func buildWhereClause(filter api.LogFilter) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	addIn := func(column string, values []string) {
		if len(values) == 0 {
			return
		}
		placeholders := strings.TrimRight(strings.Repeat("?,", len(values)), ",")
		clauses = append(clauses, fmt.Sprintf("%s IN (%s)", column, placeholders))
		for _, v := range values {
			args = append(args, v)
		}
	}

	addIn("host_id", filter.HostIDs)
	addIn("fleet_id", filter.FleetIDs)
	addIn("rule_id", filter.RuleIDs)
	addIn("severity", filter.Severities)

	if len(filter.Statuses) > 0 {
		statusValues := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			statusValues[i] = string(s)
		}
		addIn("status", statusValues)
	}

	if filter.Transactional != nil {
		clauses = append(clauses, "transactional = ?")
		args = append(args, boolToInt(*filter.Transactional))
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "started_at >= ?")
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, "started_at < ?")
		args = append(args, filter.Until.UTC().Format(time.RFC3339Nano))
	}

	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// applyGetOptions delegates to [api.ResolveGetOptions], which lives in
// the api package because it accesses the unexported getOptions type.
func applyGetOptions(opts []api.GetOption) (bool, bool) {
	return api.ResolveGetOptions(opts)
}

// applyAggregateOptions delegates to [api.ResolveAggregateOptions].
func applyAggregateOptions(opts []api.AggregateOption) api.TimeBucket {
	return api.ResolveAggregateOptions(opts)
}

// Ensure SQLite satisfies the Store interface at compile time.
var _ Store = (*SQLite)(nil)

// Suppress unused-import error if database/sql is not directly used.
var _ = sql.ErrNoRows
