// SPDX-License-Identifier: AGPL-3.0-only

package readwindow

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/timestamp"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/stretchr/testify/require"

	"github.com/grafana/mimir/pkg/mimirtool/util"
)

var (
	queryStart = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	queryEnd   = queryStart.Add(time.Hour)
	queryStep  = time.Minute
	lookback   = 5 * time.Minute
)

type expectedWindow struct {
	metric     string
	kind       string
	rangeMS    int64
	offsetMS   int64
	readStart  int64
	readEnd    int64
	atModifier string // "", "timestamp", "start" or "end"
	source     string
	anchored   bool
	smoothed   bool
}

type analyzeTestCase struct {
	name                 string
	query                string
	experimental         bool
	instant              bool
	endBeforeStart       bool
	stepSet              bool
	step                 time.Duration
	lookbackSet          bool
	lookback             time.Duration
	wantErr              string
	wantWindows          []expectedWindow
	skipMinMaxCrossCheck bool
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func TestAnalyze(t *testing.T) {
	ts := time.Unix(1704000000, 0).UTC()

	testCases := []analyzeTestCase{
		{
			name:        "instant vector selector over range query",
			query:       "metric",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", readStart: ms(queryStart.Add(-lookback + time.Millisecond)), readEnd: ms(queryEnd), source: "metric"}},
		},
		{
			name:        "instant query",
			query:       "metric",
			instant:     true,
			step:        0,
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", readStart: ms(queryStart.Add(-lookback + time.Millisecond)), readEnd: ms(queryStart), source: "metric"}},
		},
		{
			name:        "range vector selector",
			query:       "rate(metric[5m])",
			wantWindows: []expectedWindow{{metric: "metric", kind: "range", rangeMS: 300000, readStart: ms(queryStart.Add(-5*time.Minute + time.Millisecond)), readEnd: ms(queryEnd), source: "metric[5m]"}},
		},
		{
			name:        "positive offset shifts reads into the past",
			query:       "metric offset 1h",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", offsetMS: 3600000, readStart: ms(queryStart.Add(-time.Hour - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-time.Hour)), source: "metric offset 1h"}},
		},
		{
			name:        "negative offset shifts reads into the future",
			query:       "metric offset -1h",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", offsetMS: -3600000, readStart: ms(queryStart.Add(time.Hour - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(time.Hour)), source: "metric offset -1h"}},
		},
		{
			name:        "range vector with positive offset",
			query:       "rate(metric[5m] offset 1h)",
			wantWindows: []expectedWindow{{metric: "metric", kind: "range", rangeMS: 300000, offsetMS: 3600000, readStart: ms(queryStart.Add(-time.Hour - 5*time.Minute + time.Millisecond)), readEnd: ms(queryEnd.Add(-time.Hour)), source: "metric[5m] offset 1h"}},
		},
		{
			name:  "@ timestamp pins the read window",
			query: "metric @ 1704000000",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "instant", atModifier: "timestamp",
				readStart: ms(ts.Add(-lookback + time.Millisecond)), readEnd: ms(ts), source: "metric @ 1704000000",
			}},
		},
		{
			name:  "@ timestamp with offset still applies the selector offset",
			query: "metric @ 1704000000 offset 1h",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "instant", offsetMS: 3600000, atModifier: "timestamp",
				readStart: ms(ts.Add(-time.Hour - lookback + time.Millisecond)), readEnd: ms(ts.Add(-time.Hour)), source: "metric @ 1704000000 offset 1h",
			}},
		},
		{
			name:        "@ start() resolves to query start",
			query:       "metric @ start()",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", atModifier: "start", readStart: ms(queryStart.Add(-lookback + time.Millisecond)), readEnd: ms(queryStart), source: "metric @ start()"}},
		},
		{
			name:        "@ end() offset resolves to query end and shifts",
			query:       "metric @ end() offset 1h",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", offsetMS: 3600000, atModifier: "end", readStart: ms(queryEnd.Add(-time.Hour - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-time.Hour)), source: "metric @ end() offset 1h"}},
		},
		{
			name:        "offset before @ end() has the same window",
			query:       "metric offset 1h @ end()",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", offsetMS: 3600000, atModifier: "end", readStart: ms(queryEnd.Add(-time.Hour - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-time.Hour)), source: "metric offset 1h @ end()"}},
		},
		{
			name:  "nested subquery extends reads by accumulated range and offset",
			query: "max_over_time((rate(metric[1m]))[10m:1m] offset 2h)",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "range", rangeMS: 60000, offsetMS: 0,
				readStart: ms(queryStart.Add(-2*time.Hour - 10*time.Minute - time.Minute + time.Millisecond)),
				readEnd:   ms(queryEnd.Add(-2 * time.Hour)),
				source:    "metric[1m]",
			}},
		},
		{
			name:  "@ on enclosing subquery resets and anchors accumulated modifiers",
			query: "max_over_time((metric)[10m:1m] @ 1704000000)",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "instant",
				readStart: ms(ts.Add(-10*time.Minute - lookback + time.Millisecond)), readEnd: ms(ts),
				source: "metric",
			}},
		},
		{
			name:  "nested subquery @ followed by outer subquery offset and range",
			query: "max_over_time((max_over_time((metric)[5m:1m] @ 1704000000))[20m:5m] offset 2h)",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "instant",
				// Inner @ subquery resets accumulation to its own range/offset; outer
				// subquery modifiers do not shift the anchored selector.
				readStart: ms(ts.Add(-5*time.Minute - lookback + time.Millisecond)), readEnd: ms(ts),
				source: "metric",
			}},
		},
		{
			name:  "same metric name in different expression positions yields separate windows",
			query: "metric offset 1h + metric offset 2h",
			wantWindows: []expectedWindow{
				{metric: "metric", kind: "instant", offsetMS: 3600000, readStart: ms(queryStart.Add(-time.Hour - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-time.Hour)), source: "metric offset 1h"},
				{metric: "metric", kind: "instant", offsetMS: 7200000, readStart: ms(queryStart.Add(-2*time.Hour - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-2 * time.Hour)), source: "metric offset 2h"},
			},
		},
		{
			name:        "anchored range vector extends the start by lookback too",
			query:       "rate(metric[5m] anchored)",
			wantWindows: []expectedWindow{{metric: "metric", kind: "range", rangeMS: 300000, anchored: true, readStart: ms(queryStart.Add(-lookback - 5*time.Minute + time.Millisecond)), readEnd: ms(queryEnd), source: "metric[5m]"}},
		},
		{
			name:        "smoothed range vector extends both sides by lookback",
			query:       "rate(metric[5m] smoothed)",
			wantWindows: []expectedWindow{{metric: "metric", kind: "range", rangeMS: 300000, smoothed: true, readStart: ms(queryStart.Add(-lookback - 5*time.Minute + time.Millisecond)), readEnd: ms(queryEnd.Add(lookback)), source: "metric[5m]"}},
		},
		{
			name:        "smoothed instant selector extends end by lookback",
			query:       "metric smoothed",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", smoothed: true, readStart: ms(queryStart.Add(-lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(lookback)), source: "metric"}},
		},
		{
			name:        "matcher only selector",
			query:       `{job="api"}`,
			wantWindows: []expectedWindow{{metric: "", kind: "instant", readStart: ms(queryStart.Add(-lookback + time.Millisecond)), readEnd: ms(queryEnd), source: `{job="api"}`}},
		},
		{
			name:        "duration expression in offset is evaluated from query parameters",
			query:       "metric offset (1h / 2)",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", offsetMS: 1800000, readStart: ms(queryStart.Add(-30*time.Minute - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-30 * time.Minute)), source: "metric offset (1h / 2)"}},
		},
		{
			name:        "range() duration expression resolves to the query range",
			query:       "rate(metric[range()])",
			wantWindows: []expectedWindow{{metric: "metric", kind: "range", rangeMS: 3600000, readStart: ms(queryStart.Add(-time.Hour + time.Millisecond)), readEnd: ms(queryEnd), source: "metric[range()]"}},
		},
		{
			name:        "step() duration expression resolves to the query step",
			query:       "metric offset (step() * 2)",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", offsetMS: 120000, readStart: ms(queryStart.Add(-2*time.Minute - lookback + time.Millisecond)), readEnd: ms(queryEnd.Add(-2 * time.Minute)), source: "metric offset (step() * 2)"}},
		},
		{
			name:  "selector @ timestamp inside a subquery ignores the subquery range and offset",
			query: "max_over_time((metric @ 1704000000)[10m:1m] offset 2h)",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "instant", atModifier: "timestamp",
				readStart: ms(ts.Add(-lookback + time.Millisecond)), readEnd: ms(ts),
				source: "metric @ 1704000000",
			}},
		},
		{
			name:  "negative range-vector offset inside a subquery shifts reads future",
			query: "max_over_time((rate(metric[1m] offset -1h))[2h:5m])",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "range", rangeMS: 60000, offsetMS: -3600000,
				readStart: ms(queryStart.Add(-time.Hour - time.Minute + time.Millisecond)),
				readEnd:   ms(queryEnd.Add(time.Hour)),
				source:    "metric[1m] offset -1h",
			}},
		},
		{
			name:  "two nested subqueries accumulate ranges and offsets",
			query: "rate(sum(max_over_time((metric)[10m:1m]))[30m:5m] offset 2h)",
			wantWindows: []expectedWindow{{
				metric: "metric", kind: "instant",
				readStart: ms(queryStart.Add(-2*time.Hour - 45*time.Minute + time.Millisecond)),
				readEnd:   ms(queryEnd.Add(-2 * time.Hour)),
				source:    "metric",
			}},
		},
		{
			name:        "@ end() on subquery anchors to query end",
			query:       "max_over_time((metric)[10m:1m] @ end())",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", readStart: ms(queryEnd.Add(-10*time.Minute - lookback + time.Millisecond)), readEnd: ms(queryEnd), source: "metric"}},
		},
		{
			name:        "anchored instant selector reads like a regular instant selector",
			query:       "metric anchored",
			wantWindows: []expectedWindow{{metric: "metric", kind: "instant", anchored: true, readStart: ms(queryStart.Add(-lookback + time.Millisecond)), readEnd: ms(queryEnd), source: "metric"}},
		},
		{
			name:                 "expression without selectors produces an empty selector list",
			query:                "1 + 2",
			wantWindows:          nil,
			skipMinMaxCrossCheck: true,
		},
		{
			name:         "info() is rejected because its metadata reads are data dependent",
			query:        `info(metric, {job="api"})`,
			experimental: true,
			wantErr:      "unsupported PromQL expression",
		},
		{
			name:    "syntax error is reported",
			query:   "rate(",
			wantErr: "invalid PromQL expression",
		},
		{
			name:    "unclosed selector is reported",
			query:   "metric[",
			wantErr: "invalid PromQL expression",
		},
		{
			name:    "division by zero in duration expression is reported",
			query:   "metric offset (1h / 0)",
			wantErr: "invalid PromQL expression",
		},
		{
			name:    "negative range duration expression is reported",
			query:   "rate(metric[(1h - 2h)])",
			wantErr: "invalid PromQL expression",
		},
		{
			name:           "end before start is reported",
			query:          "metric",
			endBeforeStart: true,
			step:           queryStep,
			lookback:       lookback,
			wantErr:        "invalid time parameters",
		},
		{
			name:     "zero step for range query is reported",
			query:    "metric",
			stepSet:  true,
			step:     0,
			lookback: lookback,
			wantErr:  "invalid time parameters",
		},
		{
			name:     "non-zero step for instant query is reported",
			query:    "metric",
			instant:  true,
			stepSet:  true,
			step:     time.Minute,
			lookback: lookback,
			wantErr:  "invalid time parameters",
		},
		{
			name:     "negative lookback is reported",
			query:    "metric",
			step:     queryStep,
			lookback: -time.Second,
			wantErr:  "invalid time parameters",
		},
		{
			name:        "zero lookback is reported",
			query:       "metric",
			step:        queryStep,
			lookbackSet: true,
			lookback:    0,
			wantErr:     "invalid time parameters",
		},
		{
			name:     "empty query is reported",
			query:    "   ",
			step:     queryStep,
			lookback: lookback,
			wantErr:  "query must not be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			start, end := queryStart, queryEnd
			step := queryStep
			if tc.instant {
				end = start
				step = 0
			}
			if tc.endBeforeStart {
				end = start.Add(-time.Hour)
			}
			if tc.stepSet {
				step = tc.step
			}
			lb := lookback
			if tc.lookbackSet || tc.lookback != 0 {
				lb = tc.lookback
			}

			result, err := Analyze(Params{
				Query:                       tc.query,
				Start:                       start,
				End:                         end,
				Step:                        step,
				LookbackDelta:               lb,
				EnableExperimentalFunctions: tc.experimental,
			})
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.query, result.Query)
			require.Equal(t, ms(start), result.StartMs)
			require.Equal(t, ms(end), result.EndMs)
			require.Equal(t, lb.Milliseconds(), result.LookbackDeltaMs)

			require.Len(t, result.Selectors, len(tc.wantWindows))
			var prevEnd int
			for i, want := range tc.wantWindows {
				got := result.Selectors[i]
				require.Equal(t, i, got.Index, "selector index")
				require.Equal(t, want.metric, got.MetricName, "metric name for selector %d", i)
				require.Equal(t, want.kind, got.Kind, "kind for selector %d", i)
				require.Equal(t, want.rangeMS, got.RangeMs, "range for selector %d", i)
				require.Equal(t, want.offsetMS, got.OffsetMs, "offset for selector %d", i)
				require.Equal(t, want.readStart, got.ReadStartMs, "read start for selector %d", i)
				require.Equal(t, want.readEnd, got.ReadEndMs, "read end for selector %d", i)
				require.Equal(t, want.source, got.Source, "source for selector %d", i)
				require.Equal(t, want.anchored, got.Anchored, "anchored for selector %d", i)
				require.Equal(t, want.smoothed, got.Smoothed, "smoothed for selector %d", i)
				if want.atModifier == "" {
					require.Nil(t, got.At, "at modifier for selector %d", i)
				} else {
					require.NotNil(t, got.At, "at modifier for selector %d", i)
					require.Equal(t, want.atModifier, got.At.Modifier, "at modifier kind for selector %d", i)
				}
				// Positions are ordered and locate the source substring.
				require.GreaterOrEqual(t, got.PositionStart, 0)
				require.LessOrEqual(t, got.PositionStart, got.PositionEnd)
				require.GreaterOrEqual(t, got.PositionStart, prevEnd, "selector positions must be ordered")
				prevEnd = got.PositionEnd
				require.Equal(t, tc.query[got.PositionStart:got.PositionEnd], got.Source)
				// Bounds are inclusive millisecond timestamps.
				require.LessOrEqual(t, got.ReadStartMs, got.ReadEndMs)
				require.Equal(t, formatMillis(got.ReadStartMs), got.ReadStart)
				require.Equal(t, formatMillis(got.ReadEndMs), got.ReadEnd)
			}

			if len(tc.wantWindows) > 0 {
				var wantMin, wantMax int64
				for i, want := range tc.wantWindows {
					if i == 0 || want.readStart < wantMin {
						wantMin = want.readStart
					}
					if i == 0 || want.readEnd > wantMax {
						wantMax = want.readEnd
					}
				}
				require.NotNil(t, result.QueryReadStartMs)
				require.NotNil(t, result.QueryReadEndMs)
				require.Equal(t, wantMin, *result.QueryReadStartMs)
				require.Equal(t, wantMax, *result.QueryReadEndMs)
			} else {
				require.Nil(t, result.QueryReadStartMs)
				require.Nil(t, result.QueryReadEndMs)
			}

			if !tc.skipMinMaxCrossCheck {
				crossCheckAgainstEngine(t, tc.query, start, end, step, lb, tc.experimental, result)
			}

			// JSON output must be stable and round-trip.
			first, err := json.MarshalIndent(result, "", "  ")
			require.NoError(t, err)
			second, err := json.MarshalIndent(result, "", "  ")
			require.NoError(t, err)
			require.Equal(t, string(first), string(second))
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(first, &decoded))
			require.Equal(t, inclusive, result.Boundaries.Start)
			require.Equal(t, inclusive, result.Boundaries.End)
			require.NotEmpty(t, result.Boundaries.Description)
		})
	}
}

// crossCheckAgainstEngine compares the per-selector windows' global minimum and
// maximum against Prometheus' own promql.FindMinMaxTime, which is the exact
// computation the engine uses for the query-wide storage time range.
func crossCheckAgainstEngine(t *testing.T, query string, start, end time.Time, step, lookback time.Duration, experimental bool, result *Result) {
	t.Helper()

	promqlParser := util.CreatePromQLParser(experimental)
	expr, err := promqlParser.ParseExpr(query)
	require.NoError(t, err)
	expr, err = promql.PreprocessExpr(expr, start, end, step)
	require.NoError(t, err)

	engineMin, engineMax := promql.FindMinMaxTime(&parser.EvalStmt{
		Expr:          expr,
		Start:         start,
		End:           end,
		Interval:      step,
		LookbackDelta: lookback,
	})

	var gotMin, gotMax int64
	for i, selector := range result.Selectors {
		if i == 0 || selector.ReadStartMs < gotMin {
			gotMin = selector.ReadStartMs
		}
		if i == 0 || selector.ReadEndMs > gotMax {
			gotMax = selector.ReadEndMs
		}
	}
	require.Equal(t, engineMin, gotMin, "global read start must match promql.FindMinMaxTime")
	require.Equal(t, engineMax, gotMax, "global read end must match promql.FindMinMaxTime")
}

func TestParseTime(t *testing.T) {
	got, err := ParseTime("2024-01-01T00:00:00Z")
	require.NoError(t, err)
	require.Equal(t, ms(queryStart), ms(got))

	got, err = ParseTime("1704067200")
	require.NoError(t, err)
	require.Equal(t, int64(1704067200000), got.UnixMilli())

	got, err = ParseTime("1704067200.500")
	require.NoError(t, err)
	require.Equal(t, int64(1704067200500), got.UnixMilli())

	_, err = ParseTime("not-a-time")
	require.Error(t, err)

	_, err = ParseTime("NaN")
	require.Error(t, err)
}

func TestSubqueryContextIsRendered(t *testing.T) {
	result, err := Analyze(Params{
		Query:         "sum(max_over_time((rate(metric[1m]))[10m:1m] offset 2h))",
		Start:         queryStart,
		End:           queryEnd,
		Step:          queryStep,
		LookbackDelta: lookback,
	})
	require.NoError(t, err)
	require.Len(t, result.Selectors, 1)
	require.Equal(t, []string{
		"aggregation:sum",
		"function:max_over_time",
		"subquery:10m:1m",
		"paren",
		"function:rate",
		"range:1m",
	}, result.Selectors[0].Context)
}

func TestSelectorMatchersAreCanonical(t *testing.T) {
	result, err := Analyze(Params{
		Query:         `metric{b="2",a="1"}`,
		Start:         queryStart,
		End:           queryEnd,
		Step:          queryStep,
		LookbackDelta: lookback,
	})
	require.NoError(t, err)
	require.Equal(t, `{__name__="metric",a="1",b="2"}`, result.Selectors[0].Matchers)

	// Keep timestamp package referenced for documentation of the ms basis.
	require.Equal(t, int64(1704067200000), timestamp.FromTime(queryStart))
}
