package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// LogQuery is the read-side interface over the persisted transaction log.
// It is the foundation of OpenWatch's Eye identity (see
// docs/OPENWATCH_VISION.md §3.1): every transaction Kensa has executed
// is queryable here, with pre-state, apply detail, validation results,
// commit/rollback decision, and the signed evidence envelope.
//
// The implementation lives in internal/store and lands in Week 22 per
// docs/KENSA_GO_DAY1_PLAN.md §11.5. The interface is stable from
// commit 1.
type LogQuery interface {
	// Query returns transactions matching filter, paginated by page.
	// An empty filter matches all transactions.
	Query(ctx context.Context, filter LogFilter, page Page) (*QueryResult, error)

	// Get returns the [TransactionRecord] for txnID. Without options,
	// the result includes the full evidence envelope and pre-state
	// bundles — the correct default for audit export. List views may
	// opt out via [WithoutEnvelope] and [WithoutPreStates] for
	// performance.
	Get(ctx context.Context, txnID uuid.UUID, opts ...GetOption) (*TransactionRecord, error)

	// Aggregate returns posture summaries grouped by groupBy over the
	// time range in filter. The transaction-log spec
	// (specs/store/transaction_log.spec.yaml) AC-06 commits Aggregate
	// to a 500ms p95 against a 500K-row, 1000-host corpus.
	Aggregate(ctx context.Context, filter LogFilter, groupBy AggregateKey, opts ...AggregateOption) (*AggregateResult, error)
}

// FrameworkRef is a structured reference to a compliance-framework
// control. Storing the framework and control as separate fields lets
// every consumer filter by tuple without parsing opaque strings.
type FrameworkRef struct {
	// FrameworkID identifies the framework and version, for example
	// "cis_rhel9_v2", "stig_rhel9_v2r7", or "nist_800_53_r5".
	FrameworkID string
	// ControlID is the framework's native control identifier, for
	// example "5.2.3", "V-257947", or "AC-6(2)".
	ControlID string
}

// LogFilter selects transactions across multiple dimensions. Empty
// fields impose no restriction on that dimension.
type LogFilter struct {
	HostIDs       []string
	FleetIDs      []string
	RuleIDs       []string
	FrameworkRefs []FrameworkRef
	Statuses      []TransactionStatus
	Phases        []Phase  // capture, apply, validate, commit, rollback
	Severities    []string // critical, high, medium, low
	Mechanisms    []string
	// Transactional is a tri-state filter: nil leaves the dimension
	// unrestricted; non-nil restricts to transactions whose
	// [Transaction.Transactional] equals the pointed-to value.
	Transactional *bool
	Since         time.Time
	Until         time.Time
}

// Page controls pagination for [LogQuery.Query].
type Page struct {
	// Offset is the zero-based row index to start returning from.
	Offset int
	// Limit caps the number of rows in the response.
	Limit int
}

// QueryResult is the paginated response from [LogQuery.Query].
type QueryResult struct {
	// Transactions are the rows in this page.
	Transactions []TransactionRecord
	// Total is the unpaginated count of rows that matched the filter.
	Total int
	// Offset and Limit echo the requested [Page].
	Offset int
	Limit  int
}

// TransactionRecord is the hydrated record returned by [LogQuery.Get]
// and inside each [QueryResult]. The [TransactionRecord.PreStates] and
// [TransactionRecord.Envelope] fields are populated by default and may
// be omitted via [WithoutPreStates] and [WithoutEnvelope].
type TransactionRecord struct {
	ID            uuid.UUID
	RuleID        string
	HostID        string
	FleetID       string
	Status        TransactionStatus
	Transactional bool
	// Severity is denormalized from the rule at write time so
	// aggregations need not join against the rule corpus.
	Severity      string
	StartedAt     time.Time
	FinishedAt    time.Time
	Steps         []StepResult
	PreStates     []PreState        // Omitted if [WithoutPreStates] passed.
	Envelope      *EvidenceEnvelope // Omitted if [WithoutEnvelope] passed.
	FrameworkRefs []FrameworkRef
}

// AggregateKey enumerates the supported aggregation shapes for
// [LogQuery.Aggregate]. Each key has a dedicated optimized query path;
// arbitrary aggregations are not supported through this interface.
type AggregateKey string

// Supported [AggregateKey] values.
const (
	// AggregateByHost groups transactions by [TransactionRecord.HostID].
	AggregateByHost AggregateKey = "by_host"
	// AggregateByRule groups by [TransactionRecord.RuleID].
	AggregateByRule AggregateKey = "by_rule"
	// AggregateByFrameworkControl groups by [FrameworkRef].
	AggregateByFrameworkControl AggregateKey = "by_framework_control"
	// AggregateByHostThenFrameworkControl is a two-level grouping for
	// the compliance-officer "which control is failing on which host"
	// view.
	AggregateByHostThenFrameworkControl AggregateKey = "by_host_then_framework_control"
	// AggregateByRuleThenStatusOverTime is a time-bucketed grouping
	// for drift views; requires [WithTimeBucket].
	AggregateByRuleThenStatusOverTime AggregateKey = "by_rule_then_status_over_time"
)

// TimeBucket controls time-based aggregations. Required when the
// [AggregateKey] is a *OverTime variant. Callers must specify
// explicitly; the engine does not infer bucket size from the date
// range.
type TimeBucket string

// Supported [TimeBucket] values.
const (
	HourBucket TimeBucket = "hour"
	DayBucket  TimeBucket = "day"
	WeekBucket TimeBucket = "week"
)

// AggregateResult is the response from [LogQuery.Aggregate]. The shape
// of [AggregateResult.Rows] varies by [AggregateResult.GroupBy];
// callers interpret per the [AggregateKey] documentation.
type AggregateResult struct {
	GroupBy AggregateKey
	// TimeBucket is empty for non-time aggregations.
	TimeBucket TimeBucket
	Rows       []AggregateRow
}

// AggregateRow is one row of an [AggregateResult]. Fields populated
// depend on the [AggregateKey] of the parent result.
type AggregateRow struct {
	HostID       string                    `json:"host_id,omitempty"`
	RuleID       string                    `json:"rule_id,omitempty"`
	FrameworkRef *FrameworkRef             `json:"framework_ref,omitempty"`
	TimeBucket   *time.Time                `json:"time_bucket,omitempty"`
	StatusCounts map[TransactionStatus]int `json:"status_counts"`
	TotalCount   int                       `json:"total_count"`
}

// getOptions carries [LogQuery.Get] modifier flags.
type getOptions struct {
	includeEnvelope  bool
	includePreStates bool
}

// GetOption is a functional option for [LogQuery.Get]. The default
// (no options) returns the full record, which is correct for audit
// export.
type GetOption func(*getOptions)

// WithEnvelope explicitly opts in to envelope inclusion. The default
// already includes the envelope, so this option exists for
// readability when assembling option lists conditionally.
func WithEnvelope() GetOption { return func(o *getOptions) { o.includeEnvelope = true } }

// WithoutEnvelope omits [TransactionRecord.Envelope] from the
// response, reducing payload size for list views.
func WithoutEnvelope() GetOption { return func(o *getOptions) { o.includeEnvelope = false } }

// WithoutPreStates omits [TransactionRecord.PreStates] from the
// response, reducing payload size for list views.
func WithoutPreStates() GetOption { return func(o *getOptions) { o.includePreStates = false } }

// aggregateOptions carries [LogQuery.Aggregate] modifier flags.
type aggregateOptions struct {
	bucket TimeBucket
}

// AggregateOption is a functional option for [LogQuery.Aggregate].
type AggregateOption func(*aggregateOptions)

// WithTimeBucket specifies the bucket granularity for time-based
// aggregations. Required when [AggregateKey] is a *OverTime variant.
func WithTimeBucket(b TimeBucket) AggregateOption {
	return func(o *aggregateOptions) { o.bucket = b }
}
