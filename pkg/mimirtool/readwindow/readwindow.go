// SPDX-License-Identifier: AGPL-3.0-only

// Package readwindow statically computes the time ranges that a PromQL
// expression has to read from storage for every instant or range vector
// selector. It performs the same computation as the PromQL engine when it
// builds storage SelectHints, but it does so offline and never executes the
// query.
package readwindow

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/grafana/mimir/pkg/mimirtool/util"
)

// Params holds the PromQL expression and the query parameters used to compute
// the storage read windows.
type Params struct {
	// Query is the PromQL expression to analyze.
	Query string
	// Start and End are the query's evaluation time range. When they are
	// equal, the query is treated as an instant query.
	Start, End time.Time
	// Step is the query evaluation step. It must be 0 for an instant query
	// (Start == End) and greater than 0 for a range query.
	Step time.Duration
	// LookbackDelta is the staleness lookback delta applied to instant
	// selectors (5 minutes in Prometheus by default).
	LookbackDelta time.Duration
	// EnableExperimentalFunctions enables parsing experimental PromQL
	// functions, mirroring the "promql format" command.
	EnableExperimentalFunctions bool
}

// AtModifier describes the @ time modifier attached to a selector.
type AtModifier struct {
	// Modifier is "timestamp" for "@ <unix-timestamp>", "start" for
	// "@ start()" or "end" for "@ end()".
	Modifier string `json:"modifier"`
	// TimestampMs is the resolved modifier time in Unix milliseconds. For
	// "@ start()" and "@ end()" it is the query start/end.
	TimestampMs int64 `json:"timestamp_ms"`
	// Timestamp is the RFC3339 UTC rendering of TimestampMs.
	Timestamp string `json:"timestamp"`
}

// SelectorWindow is the storage read window of a single instant or range
// vector selector.
type SelectorWindow struct {
	// Index is the zero-based position of the selector in a depth-first
	// traversal of the expression, which is stable for a given query.
	Index int `json:"index"`
	// PositionStart and PositionEnd are the selector's byte offsets in the
	// query string: Source is query[PositionStart:PositionEnd].
	PositionStart int `json:"position_start"`
	PositionEnd   int `json:"position_end"`
	// Source is the exact selector substring of the input query.
	Source string `json:"source"`
	// MetricName is the selector's metric name, or an empty string for a
	// matcher-only selector such as {job="api"}.
	MetricName string `json:"metric_name"`
	// Matchers is the canonical, sorted rendering of all label matchers,
	// including an explicit __name__ matcher when present.
	Matchers string `json:"matchers"`
	// Kind is "instant" for an instant vector selector and "range" for a
	// range vector selector.
	Kind string `json:"kind"`
	// RangeMs is the range vector window in milliseconds. It is 0 for an
	// instant selector.
	RangeMs int64 `json:"range_ms"`
	// OffsetMs is the selector offset in milliseconds. Positive offsets
	// shift reads into the past, negative offsets into the future.
	OffsetMs int64 `json:"offset_ms"`
	// At describes the selector's @ modifier, or nil when there is none.
	At *AtModifier `json:"at"`
	// Anchored and Smoothed report the experimental anchored/smoothed
	// selector modifiers.
	Anchored bool `json:"anchored"`
	Smoothed bool `json:"smoothed"`
	// Context describes the expression nodes enclosing the selector, from
	// the outermost node to the immediate parent. It disambiguates metrics
	// with the same name used in different expression positions.
	Context []string `json:"context"`
	// ReadStartMs and ReadEndMs are the earliest and latest sample
	// timestamps, in Unix milliseconds, that the PromQL engine requests
	// from storage. Both bounds are inclusive.
	ReadStartMs int64 `json:"read_start_ms"`
	ReadEndMs   int64 `json:"read_end_ms"`
	// ReadStart and ReadEnd are the RFC3339 UTC renderings of ReadStartMs
	// and ReadEndMs.
	ReadStart string `json:"read_start"`
	ReadEnd   string `json:"read_end"`
}

// Boundaries documents the meaning of the read window time bounds.
type Boundaries struct {
	// Start and End document the inclusivity of the read window bounds.
	Start string `json:"start"`
	End   string `json:"end"`
	// Description explains how the bounds are derived.
	Description string `json:"description"`
}

// Result is the stable JSON output of the read-window analysis.
type Result struct {
	// Query is the analyzed PromQL expression.
	Query string `json:"query"`
	// StartMs, EndMs, Start and End echo the (millisecond-truncated) query
	// time range.
	StartMs int64  `json:"start_ms"`
	EndMs   int64  `json:"end_ms"`
	Start   string `json:"start"`
	End     string `json:"end"`
	// StepMs echoes the query step in milliseconds.
	StepMs int64 `json:"step_ms"`
	// LookbackDeltaMs echoes the staleness lookback delta in milliseconds.
	LookbackDeltaMs int64 `json:"lookback_delta_ms"`
	// QueryReadStartMs and QueryReadEndMs are the minimum and maximum read
	// bounds across all selectors. They are null when the expression has no
	// selector.
	QueryReadStartMs *int64 `json:"query_read_start_ms"`
	QueryReadEndMs   *int64 `json:"query_read_end_ms"`
	// Boundaries documents the read window bound semantics.
	Boundaries Boundaries `json:"boundaries"`
	// Selectors contains one entry per data selector, in depth-first
	// traversal order.
	Selectors []*SelectorWindow `json:"selectors"`
}

const (
	rfc3339Millis = "2006-01-02T15:04:05.000Z07:00"
	inclusive     = "inclusive"

	boundaryDescription = "Read windows are the inclusive [read_start_ms, read_end_ms] millisecond " +
		"timestamp ranges that the PromQL engine passes to storage Select calls, covering every " +
		"evaluation timestamp in the query range. A lookback or range-vector window excludes the " +
		"sample exactly on its lower edge, which the engine encodes by subtracting one fewer " +
		"millisecond from read_start_ms. Positive offsets shift reads into the past; negative " +
		"offsets shift reads into the future. @ modifiers pin reads to a single timestamp; nested " +
		"subqueries extend reads by the sum of their ranges and offsets until an @ modifier resets " +
		"the accumulation."
)

// ParseTime parses a query time provided on the command line. It accepts
// RFC3339 timestamps (for example "2024-01-01T00:00:00Z") and Unix times in
// seconds, which may contain a fractional part (for example "1704067200" or
// "1704067200.500").
func ParseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	secs, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q is neither an RFC3339 timestamp nor Unix seconds: %w", s, err)
	}
	if math.IsNaN(secs) || math.IsInf(secs, 0) {
		return time.Time{}, fmt.Errorf("time %q is not a finite Unix timestamp", s)
	}
	return timestamp.Time(timestamp.FromFloatSeconds(secs)), nil
}

func formatMillis(ms int64) string {
	return timestamp.Time(ms).Format(rfc3339Millis)
}

func durationMillis(d time.Duration) int64 {
	return int64(d / time.Millisecond)
}

// Analyze parses and analyzes the given PromQL expression and returns one
// read window per data selector. It returns an error for syntax errors,
// invalid time parameters, or expressions whose storage reads cannot be
// computed statically; it never silently omits a read window and never
// executes the query.
func Analyze(params Params) (*Result, error) {
	startMs, endMs, err := validateParams(params)
	if err != nil {
		return nil, err
	}

	promqlParser := util.CreatePromQLParser(params.EnableExperimentalFunctions)
	expr, err := promqlParser.ParseExpr(params.Query)
	if err != nil {
		return nil, fmt.Errorf("invalid PromQL expression: %w", err)
	}

	// Run the engine's own preprocessing so that @ start()/@ end() modifiers
	// and duration expressions (for example "offset (1h / 2)",
	// "offset step()") are resolved exactly as they are during query
	// execution. No queryable is involved and no query is executed.
	expr, err = promql.PreprocessExpr(expr, timestamp.Time(startMs), timestamp.Time(endMs), params.Step)
	if err != nil {
		return nil, fmt.Errorf("invalid PromQL expression: %w", err)
	}

	if err := rejectUnsupported(expr); err != nil {
		return nil, err
	}

	result := &Result{
		Query:           params.Query,
		StartMs:         startMs,
		EndMs:           endMs,
		Start:           formatMillis(startMs),
		End:             formatMillis(endMs),
		StepMs:          durationMillis(params.Step),
		LookbackDeltaMs: durationMillis(params.LookbackDelta),
		Boundaries: Boundaries{
			Start:       inclusive,
			End:         inclusive,
			Description: boundaryDescription,
		},
		Selectors: []*SelectorWindow{},
	}

	lookbackDelta := params.LookbackDelta
	var (
		walkErr         error
		evalRange       time.Duration
		enclosingMatrix *parser.MatrixSelector
	)
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if walkErr != nil {
			return walkErr
		}
		switch n := node.(type) {
		case *parser.MatrixSelector:
			evalRange = n.Range
			enclosingMatrix = n
		case *parser.VectorSelector:
			readStart, readEnd := selectorBounds(startMs, endMs, n, path, evalRange, lookbackDelta)
			context, err := formatContext(path)
			if err != nil {
				walkErr = err
				return err
			}
			result.Selectors = append(result.Selectors, buildSelectorWindow(len(result.Selectors), params.Query, n, enclosingMatrix, context, readStart, readEnd))
			evalRange = 0
			enclosingMatrix = nil
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	for _, selector := range result.Selectors {
		if result.QueryReadStartMs == nil || selector.ReadStartMs < *result.QueryReadStartMs {
			start := selector.ReadStartMs
			result.QueryReadStartMs = &start
		}
		if result.QueryReadEndMs == nil || selector.ReadEndMs > *result.QueryReadEndMs {
			end := selector.ReadEndMs
			result.QueryReadEndMs = &end
		}
	}

	return result, nil
}

func validateParams(params Params) (int64, int64, error) {
	if strings.TrimSpace(params.Query) == "" {
		return 0, 0, fmt.Errorf("query must not be empty")
	}
	if params.Start.IsZero() {
		return 0, 0, fmt.Errorf("invalid time parameters: start time is required")
	}
	if params.End.IsZero() {
		return 0, 0, fmt.Errorf("invalid time parameters: end time is required")
	}
	if params.LookbackDelta <= 0 {
		return 0, 0, fmt.Errorf("invalid time parameters: lookback delta must be greater than 0, got %s", params.LookbackDelta)
	}
	if params.Step < 0 {
		return 0, 0, fmt.Errorf("invalid time parameters: step must not be negative, got %s", params.Step)
	}

	startMs := timestamp.FromTime(params.Start)
	endMs := timestamp.FromTime(params.End)
	if endMs < startMs {
		return 0, 0, fmt.Errorf("invalid time parameters: end (%s) must not be before start (%s)", formatMillis(endMs), formatMillis(startMs))
	}
	if startMs == endMs && params.Step != 0 {
		return 0, 0, fmt.Errorf("invalid time parameters: step must be 0 for an instant query (start == end), got %s", params.Step)
	}
	if startMs != endMs && params.Step == 0 {
		return 0, 0, fmt.Errorf("invalid time parameters: step must be greater than 0 for a range query (start < end)")
	}
	return startMs, endMs, nil
}

// rejectUnsupported rejects expressions whose storage reads cannot be
// enumerated statically. The info() function issues an additional metadata
// series selection whose matchers and time reference are derived from the
// data read at evaluation time, so reporting only the syntactic selectors
// would silently undercount the reads.
func rejectUnsupported(expr parser.Expr) error {
	var unsupported error
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if unsupported != nil {
			return unsupported
		}
		if call, ok := node.(*parser.Call); ok && call.Func != nil && call.Func.Name == "info" {
			unsupported = fmt.Errorf("unsupported PromQL expression: the info() function performs an additional data-dependent metadata read that cannot be computed offline; rewrite the query without info()")
			return unsupported
		}
		return nil
	})
	return unsupported
}

// subqueryTimes mirrors promql.subqueryTimes: it returns the accumulated
// offsets and ranges of all subqueries on the selector's path. A @ modifier
// on a subquery resets the accumulation and anchors it to the modifier
// timestamp.
func subqueryTimes(path []parser.Node) (time.Duration, time.Duration, *int64) {
	var (
		subqOffset, subqRange time.Duration
		ts                    int64 = math.MaxInt64
	)
	for _, node := range path {
		if n, ok := node.(*parser.SubqueryExpr); ok {
			subqOffset += n.OriginalOffset
			subqRange += n.Range
			if n.Timestamp != nil {
				subqOffset = n.OriginalOffset
				subqRange = n.Range
				ts = *n.Timestamp
			}
		}
	}
	if ts == math.MaxInt64 {
		return subqOffset, subqRange, nil
	}
	return subqOffset, subqRange, &ts
}

// selectorBounds mirrors promql.getTimeRangesForSelector, i.e. the exact
// [Start, End] milliseconds the PromQL engine provides in the storage
// SelectHints for the selector.
func selectorBounds(queryStart, queryEnd int64, vs *parser.VectorSelector, path []parser.Node, evalRange, lookbackDelta time.Duration) (int64, int64) {
	start, end := queryStart, queryEnd
	subqOffset, subqRange, subqTs := subqueryTimes(path)

	if subqTs != nil {
		// The timestamp on an enclosing subquery overrides the query range.
		start = *subqTs
		end = *subqTs
	}

	if vs.Timestamp != nil {
		// The @ timestamp on the selector overrides everything else.
		start = *vs.Timestamp
		end = *vs.Timestamp
	} else {
		offsetMillis := durationMillis(subqOffset)
		start = start - offsetMillis - durationMillis(subqRange)
		end -= offsetMillis
	}

	lookbackMillis := durationMillis(lookbackDelta)
	if evalRange == 0 {
		// Subtract one fewer millisecond than the lookback delta because a
		// sample exactly on the lookback boundary is excluded.
		start -= lookbackMillis - 1
		if vs.Smoothed {
			end += lookbackMillis
		}
	} else {
		rangeMillis := durationMillis(evalRange)
		switch {
		case vs.Anchored:
			start -= lookbackMillis + rangeMillis - 1
		case vs.Smoothed:
			start -= lookbackMillis + rangeMillis - 1
			end += lookbackMillis
		default:
			start -= rangeMillis - 1
		}
	}

	offsetMillis := durationMillis(vs.OriginalOffset)
	start -= offsetMillis
	end -= offsetMillis

	return start, end
}

func buildSelectorWindow(index int, query string, vs *parser.VectorSelector, matrix *parser.MatrixSelector, context []string, readStart, readEnd int64) *SelectorWindow {
	posRange := vs.PositionRange()
	kind := "instant"
	var rangeMillis int64
	if matrix != nil {
		posRange = matrix.PositionRange()
		kind = "range"
		rangeMillis = durationMillis(matrix.Range)
	}

	window := &SelectorWindow{
		Index:         index,
		PositionStart: int(posRange.Start),
		PositionEnd:   int(posRange.End),
		MetricName:    vs.Name,
		Matchers:      formatMatchers(vs.LabelMatchers),
		Kind:          kind,
		RangeMs:       rangeMillis,
		OffsetMs:      durationMillis(vs.OriginalOffset),
		Anchored:      vs.Anchored,
		Smoothed:      vs.Smoothed,
		Context:       context,
		ReadStartMs:   readStart,
		ReadEndMs:     readEnd,
		ReadStart:     formatMillis(readStart),
		ReadEnd:       formatMillis(readEnd),
	}
	if window.PositionStart >= 0 && window.PositionEnd <= len(query) && window.PositionStart <= window.PositionEnd {
		window.Source = query[window.PositionStart:window.PositionEnd]
	}
	if vs.Timestamp != nil || vs.StartOrEnd == parser.START || vs.StartOrEnd == parser.END {
		modifier := "timestamp"
		switch vs.StartOrEnd {
		case parser.START:
			modifier = "start"
		case parser.END:
			modifier = "end"
		}
		// PreprocessExpr resolved @ start()/@ end() into Timestamp, so the
		// timestamp is always populated here.
		var atMs int64
		if vs.Timestamp != nil {
			atMs = *vs.Timestamp
		}
		window.At = &AtModifier{
			Modifier:    modifier,
			TimestampMs: atMs,
			Timestamp:   formatMillis(atMs),
		}
	}
	return window
}

func formatMatchers(matchers []*labels.Matcher) string {
	parts := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		if matcher == nil {
			continue
		}
		parts = append(parts, matcher.String())
	}
	sort.Strings(parts)
	return "{" + strings.Join(parts, ",") + "}"
}

func formatContext(path []parser.Node) ([]string, error) {
	context := make([]string, 0, len(path))
	for _, node := range path {
		switch n := node.(type) {
		case *parser.Call:
			if n.Func != nil {
				context = append(context, "function:"+n.Func.Name)
			}
		case *parser.AggregateExpr:
			context = append(context, "aggregation:"+n.Op.String())
		case *parser.BinaryExpr:
			context = append(context, "binary:"+n.Op.String())
		case *parser.MatrixSelector:
			context = append(context, "range:"+model.Duration(n.Range).String())
		case *parser.SubqueryExpr:
			step := "default"
			if n.Step != 0 {
				step = model.Duration(n.Step).String()
			}
			context = append(context, "subquery:"+model.Duration(n.Range).String()+":"+step)
		case *parser.UnaryExpr:
			context = append(context, "unary:"+n.Op.String())
		case *parser.ParenExpr:
			context = append(context, "paren")
		case *parser.StepInvariantExpr:
			// Wrapping introduced during preprocessing; not user-visible.
		default:
			// Refuse to render a window through an AST node whose effect on
			// the evaluation time is unknown, rather than silently ignoring
			// it and potentially undercounting reads.
			return nil, fmt.Errorf("unsupported PromQL expression: cannot compute read window through %s node", strings.TrimPrefix(fmt.Sprintf("%T", node), "*parser."))
		}
	}
	return context, nil
}
