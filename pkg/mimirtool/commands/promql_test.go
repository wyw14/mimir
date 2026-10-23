// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	"github.com/grafana/mimir/pkg/mimirtool/readwindow"
)

const (
	testReadWindowStart = "2024-01-01T00:00:00Z"
	testReadWindowEnd   = "2024-01-01T01:00:00Z"
)

func newTestPromQLApp() (*kingpin.Application, *PromQLCommand) {
	app := kingpin.New("mimirtool-test", "")
	// Make parse/action errors returned instead of terminating the process.
	app.Terminate(nil)
	cmd := &PromQLCommand{}
	cmd.Register(app, EnvVarNames{})
	return app, cmd
}

func TestPromQLReadWindowCommandOutputsJSON(t *testing.T) {
	cmd := &PromQLCommand{
		query:                   "metric offset 1h + rate(other[5m])",
		readWindowStart:         testReadWindowStart,
		readWindowEnd:           testReadWindowEnd,
		readWindowStep:          time.Minute,
		readWindowLookbackDelta: 5 * time.Minute,
	}

	var buf bytes.Buffer
	require.NoError(t, cmd.runReadWindow(&buf))
	output := buf.Bytes()
	require.True(t, bytes.HasSuffix(output, []byte("\n")), "output must end with a newline")
	output = bytes.TrimSuffix(output, []byte("\n"))

	var result readwindow.Result
	require.NoError(t, json.Unmarshal(output, &result))
	require.Equal(t, cmd.query, result.Query)
	require.Equal(t, int64(1704067200000), result.StartMs)
	require.Equal(t, int64(1704070800000), result.EndMs)
	require.Equal(t, int64(60000), result.StepMs)
	require.Equal(t, int64(300000), result.LookbackDeltaMs)
	require.Equal(t, "inclusive", result.Boundaries.Start)
	require.Equal(t, "inclusive", result.Boundaries.End)
	require.Len(t, result.Selectors, 2)

	require.Equal(t, "metric", result.Selectors[0].MetricName)
	require.Equal(t, "instant", result.Selectors[0].Kind)
	require.Equal(t, int64(3600000), result.Selectors[0].OffsetMs)

	require.Equal(t, "other", result.Selectors[1].MetricName)
	require.Equal(t, "range", result.Selectors[1].Kind)
	require.Equal(t, int64(300000), result.Selectors[1].RangeMs)
	require.Equal(t, []string{"binary:+", "function:rate", "range:5m"}, result.Selectors[1].Context)

	// Same inputs must always produce byte-identical output.
	var second bytes.Buffer
	require.NoError(t, cmd.runReadWindow(&second))
	require.Equal(t, buf.String(), second.String())
}

func TestPromQLReadWindowCommandAcceptsUnixSeconds(t *testing.T) {
	cmd := &PromQLCommand{
		query:                   "metric",
		readWindowStart:         "1704067200",
		readWindowEnd:           "1704070800",
		readWindowStep:          time.Minute,
		readWindowLookbackDelta: 5 * time.Minute,
	}
	var buf bytes.Buffer
	require.NoError(t, cmd.runReadWindow(&buf))

	var result readwindow.Result
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	require.Equal(t, int64(1704067200000), result.StartMs)
	require.Equal(t, int64(1704070800000), result.EndMs)
}

func TestPromQLReadWindowCommandInstantQuery(t *testing.T) {
	cmd := &PromQLCommand{
		query:                   "metric @ start()",
		readWindowStart:         testReadWindowStart,
		readWindowEnd:           testReadWindowStart,
		readWindowStep:          0,
		readWindowLookbackDelta: 5 * time.Minute,
	}
	var buf bytes.Buffer
	require.NoError(t, cmd.runReadWindow(&buf))

	var result readwindow.Result
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	require.Len(t, result.Selectors, 1)
	require.Equal(t, int64(1704066900001), result.Selectors[0].ReadStartMs)
	require.Equal(t, int64(1704067200000), result.Selectors[0].ReadEndMs)
	require.NotNil(t, result.Selectors[0].At)
	require.Equal(t, "start", result.Selectors[0].At.Modifier)
}

func TestPromQLReadWindowCommandErrors(t *testing.T) {
	testCases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "syntax error",
			args:    []string{"promql", "read-window", "rate(", "--start", testReadWindowStart, "--end", testReadWindowEnd, "--step", "1m"},
			wantErr: "invalid PromQL expression",
		},
		{
			name:    "unsupported info function",
			args:    []string{"promql", "read-window", `info(metric, {job="api"})`, "--enable-experimental-functions", "--start", testReadWindowStart, "--end", testReadWindowEnd, "--step", "1m"},
			wantErr: "unsupported PromQL expression",
		},
		{
			name:    "invalid start time",
			args:    []string{"promql", "read-window", "metric", "--start", "not-a-time", "--end", testReadWindowEnd, "--step", "1m"},
			wantErr: "neither an RFC3339 timestamp nor Unix seconds",
		},
		{
			name:    "invalid time parameters: zero step for range query",
			args:    []string{"promql", "read-window", "metric", "--start", testReadWindowStart, "--end", testReadWindowEnd},
			wantErr: "invalid time parameters",
		},
		{
			name:    "missing end flag",
			args:    []string{"promql", "read-window", "metric", "--start", testReadWindowStart, "--step", "1m"},
			wantErr: "required flag",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := newTestPromQLApp()
			_, err := app.Parse(tc.args)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestPromQLReadWindowCommandFullParse exercises the complete kingpin parse
// path including writing to stdout, like a real CLI invocation.
func TestPromQLReadWindowCommandFullParse(t *testing.T) {
	app, _ := newTestPromQLApp()

	originalStdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = writeEnd
	defer func() { os.Stdout = originalStdout }()

	_, parseErr := app.Parse([]string{
		"promql", "read-window", "rate(metric[5m])",
		"--start", testReadWindowStart,
		"--end", testReadWindowEnd,
		"--step", "1m",
	})

	require.NoError(t, writeEnd.Close())
	os.Stdout = originalStdout
	require.NoError(t, parseErr)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(readEnd)
	require.NoError(t, err)
	require.NoError(t, readEnd.Close())

	var result readwindow.Result
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	require.Len(t, result.Selectors, 1)
	require.Equal(t, "range", result.Selectors[0].Kind)
	require.Equal(t, int64(1704066900001), result.Selectors[0].ReadStartMs)
	require.Equal(t, int64(1704070800000), result.Selectors[0].ReadEndMs)
}
