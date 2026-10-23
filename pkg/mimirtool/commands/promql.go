// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/grafana/mimir/pkg/mimirtool/readwindow"
	"github.com/grafana/mimir/pkg/mimirtool/util"
)

type PromQLCommand struct {
	query                       string
	prettyPrint                 bool
	enableExperimentalFunctions bool

	readWindowStart         string
	readWindowEnd           string
	readWindowStep          time.Duration
	readWindowLookbackDelta time.Duration
}

func (c *PromQLCommand) Register(app *kingpin.Application, _ EnvVarNames) {
	promqlCmd := app.Command("promql", "PromQL formatting and editing for Grafana Mimir.")
	promqlCmd.Flag("enable-experimental-functions", "If set, enables parsing experimental PromQL functions.").BoolVar(&c.enableExperimentalFunctions)

	// PromQL Format Query Command
	promqlFormatCmd := promqlCmd.Command("format", "Format PromQL query with Prometheus' string formatter; wrap query in quotes for CLI parsing.").Action(c.formatQuery)
	promqlFormatCmd.Flag("pretty", "use Prometheus' pretty-print formatter").BoolVar(&c.prettyPrint)
	promqlFormatCmd.Arg("query", "query to format").Required().StringVar(&c.query)

	// PromQL Read Window Command
	readWindowCmd := promqlCmd.Command(
		"read-window",
		"Offline analysis: list, for every data selector of a PromQL query, the inclusive [start,end] millisecond time range that must be read from storage. The query is not executed.",
	).Action(c.readWindow)
	readWindowCmd.Arg("query", "PromQL query to analyze; the query is parsed only and never executed.").Required().StringVar(&c.query)
	readWindowCmd.Flag("start", "Query start time as an RFC3339 timestamp (for example 2024-01-01T00:00:00Z) or Unix seconds (for example 1704067200). Equal to --end for an instant query.").
		Required().StringVar(&c.readWindowStart)
	readWindowCmd.Flag("end", "Query end time as an RFC3339 timestamp (for example 2024-01-01T01:00:00Z) or Unix seconds (for example 1704070800). Equal to --start for an instant query.").
		Required().StringVar(&c.readWindowEnd)
	readWindowCmd.Flag("step", "Query evaluation step, for example 15s or 1m. Must be greater than 0 when start < end and must be 0 (the default) for an instant query.").
		Default("0s").DurationVar(&c.readWindowStep)
	readWindowCmd.Flag("lookback-delta", "Staleness lookback delta applied to instant vector selectors, matching the PromQL engine lookback delta used when the query is executed (default 5m).").
		Default("5m").DurationVar(&c.readWindowLookbackDelta)
}

func (c *PromQLCommand) formatQuery(_ *kingpin.ParseContext) error {
	promqlParser := util.CreatePromQLParser(c.enableExperimentalFunctions)
	queryExpr, err := promqlParser.ParseExpr(c.query)
	if err != nil {
		return err
	}
	var formattedQuery string
	if c.prettyPrint {
		formattedQuery = queryExpr.Pretty(0)
	} else {
		formattedQuery = queryExpr.String()
	}

	fmt.Fprintln(os.Stdout, formattedQuery)
	return nil
}

func (c *PromQLCommand) readWindow(_ *kingpin.ParseContext) error {
	return c.runReadWindow(os.Stdout)
}

func (c *PromQLCommand) runReadWindow(w io.Writer) error {
	start, err := readwindow.ParseTime(c.readWindowStart)
	if err != nil {
		return err
	}
	end, err := readwindow.ParseTime(c.readWindowEnd)
	if err != nil {
		return err
	}

	result, err := readwindow.Analyze(readwindow.Params{
		Query:                       c.query,
		Start:                       start,
		End:                         end,
		Step:                        c.readWindowStep,
		LookbackDelta:               c.readWindowLookbackDelta,
		EnableExperimentalFunctions: c.enableExperimentalFunctions,
	})
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode read window result: %w", err)
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("failed to write read window result: %w", err)
	}
	return nil
}
