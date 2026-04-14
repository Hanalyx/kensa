package api

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// LogQuery is the read-side interface over the transaction log.
// OpenWatch's Eye identity (OPENWATCH_VISION.md §3.1) is a view over this
// interface.
//
// Implemented by internal/store/sqlite.go. The implementation lands in
// KENSA_GO_DAY1_PLAN.md Week 22. This interface is stable from commit 1.
type LogQuery interface {
	// Query returns transactions matching filter, paginated.
	Query(ctx context.Context, filter LogFilter, page Page) (*QueryResult, error)

	// Get returns a single transaction by ID. Options control inclusion
	// of the evidence envelope and pre-state bundles; default returns
	// everything (correct for audit export).
	Get(ctx context.Context, txnID uuid.UUID, opts ...GetOption) (*TransactionRecord, error)

	// Aggregate returns posture summaries grouped by AggregateKey over
	// a time range. Must satisfy the <500ms p95 target for 500K-row,
	// 1000-host corpora per transaction-log spec AC-06.
	Aggregate(ctx context.Context, filter LogFilter, groupBy AggregateKey, opts ...AggregateOption) (*AggregateResult, error)
}

// FrameworkRef is a structured framework reference. Consumers filter by
// (framework, control) tuples; opaque strings would force every consumer
// to implement parsing.
type FrameworkRef struct {
	FrameworkID string // e.g. "cis_rhel9_v2", "stig_rhel9_v2r7", "nist_800_53_r5"
	ControlID   string // e.g. "5.2.3", "V-257947", "AC-6(2)"
}

// LogFilter selects transactions across multiple dimensions. Empty
// fields are treated as "no filter on this dimension."
type LogFilter struct {
	HostIDs       []string
	FleetIDs      []string
	RuleIDs       []string
	FrameworkRefs []FrameworkRef
	Statuses      []TransactionStatus
	Phases        []Phase // capture | apply | validate | commit | rollback
	Severities    []string // critical | high | medium | low
	Mechanisms    []string
	Transactional *bool // nil = don't filter
	Since         time.Time
	Until         time.Time
}

// Page controls pagination for Query.
type Page struct {
	Offset int
	Limit  int
}

// QueryResult is the paginated Query response.
type QueryResult struct {
	Transactions []TransactionRecord
	Total        int // Unfiltered count of matching rows
	Offset       int
	Limit        int
}

// TransactionRecord is the hydrated record returned from Get and Query.
// Fields populated depend on the GetOption flags passed; Envelope and
// PreStates may be omitted for list views.
type TransactionRecord struct {
	ID            uuid.UUID
	RuleID        string
	HostID        string
	FleetID       string
	Status        TransactionStatus
	Transactional bool
	Severity      string // Denormalized from rule at write time
	StartedAt     time.Time
	FinishedAt    time.Time
	Steps         []StepResult
	PreStates     []PreState         // Omitted if WithoutPreStates passed
	Envelope      *EvidenceEnvelope  // Omitted if WithoutEnvelope passed
	FrameworkRefs []FrameworkRef
}

// AggregateKey enumerates supported aggregation shapes. Arbitrary
// aggregations are not supported through this interface — each key has
// a dedicated optimized query path.
type AggregateKey string

const (
	AggregateByHost                     AggregateKey = "by_host"
	AggregateByRule                     AggregateKey = "by_rule"
	AggregateByFrameworkControl         AggregateKey = "by_framework_control"
	AggregateByHostThenFrameworkControl AggregateKey = "by_host_then_framework_control"
	AggregateByRuleThenStatusOverTime   AggregateKey = "by_rule_then_status_over_time"
)

// TimeBucket controls time-based aggregations. Required when AggregateKey
// is a *OverTime variant. Callers must specify explicitly — the engine
// does not infer from date range.
type TimeBucket string

const (
	HourBucket TimeBucket = "hour"
	DayBucket  TimeBucket = "day"
	WeekBucket TimeBucket = "week"
)

// AggregateResult is the Aggregate response. Shape varies by groupBy;
// callers interpret Rows per the AggregateKey documentation.
type AggregateResult struct {
	GroupBy    AggregateKey
	TimeBucket TimeBucket // Empty for non-time aggregations
	Rows       []AggregateRow
}

// AggregateRow is one row of an aggregation result. Fields populated
// depend on the AggregateKey.
type AggregateRow struct {
	HostID           string             `json:"host_id,omitempty"`
	RuleID           string             `json:"rule_id,omitempty"`
	FrameworkRef     *FrameworkRef      `json:"framework_ref,omitempty"`
	TimeBucket       *time.Time         `json:"time_bucket,omitempty"`
	StatusCounts     map[TransactionStatus]int `json:"status_counts"`
	TotalCount       int                `json:"total_count"`
}

// getOptions carries Get modifier flags.
type getOptions struct {
	includeEnvelope  bool
	includePreStates bool
}

// GetOption controls payload inclusion on Get. Default includes
// everything; opt out via WithoutEnvelope / WithoutPreStates.
type GetOption func(*getOptions)

// WithEnvelope forces envelope inclusion (the default).
func WithEnvelope() GetOption { return func(o *getOptions) { o.includeEnvelope = true } }

// WithoutEnvelope omits the evidence envelope for performance on list views.
func WithoutEnvelope() GetOption { return func(o *getOptions) { o.includeEnvelope = false } }

// WithoutPreStates omits the pre-state bundle for performance.
func WithoutPreStates() GetOption { return func(o *getOptions) { o.includePreStates = false } }

// aggregateOptions carries Aggregate modifier flags.
type aggregateOptions struct {
	bucket TimeBucket
}

// AggregateOption controls aggregation behavior.
type AggregateOption func(*aggregateOptions)

// WithTimeBucket specifies the bucket granularity for time-based
// aggregations. Required when AggregateKey is a *OverTime variant.
func WithTimeBucket(b TimeBucket) AggregateOption {
	return func(o *aggregateOptions) { o.bucket = b }
}
