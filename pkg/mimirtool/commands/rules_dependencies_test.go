// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/require"

	"github.com/grafana/mimir/pkg/mimirtool/rules"
	"github.com/grafana/mimir/pkg/mimirtool/rules/dependency"
)

func TestRuleCommand_analyzeDependencies(t *testing.T) {
	dir := t.TempDir()

	fileA := filepath.Join(dir, "teamA.yaml")
	require.NoError(t, os.WriteFile(fileA, []byte(`
namespace: teamA
groups:
  - name: grp
    rules:
      - record: shared:metric
        expr: up
      - record: a:rollup
        expr: sum(shared:metric)
      - record: dyn:rollup
        expr: sum({__name__=~"foo_.+"})
`), 0o644))

	fileB := filepath.Join(dir, "teamB.yaml")
	require.NoError(t, os.WriteFile(fileB, []byte(`
namespace: teamB
groups:
  - name: grp
    rules:
      - record: shared:metric
        expr: up
      - alert: SharedHigh
        expr: shared:metric > 1
`), 0o644))

	output := filepath.Join(dir, "report.json")

	cmd := &RuleCommand{
		Backend:         rules.MimirBackend,
		logger:          log.NewNopLogger(),
		RuleFilesList:   []string{fileA, fileB},
		DepsRuleTargets: []string{"shared:metric"},
		DepsFormat:      dependenciesFormatJSON,
		DepsOutputFile:  output,
	}

	require.NoError(t, cmd.analyzeDependencies(nil))

	raw, err := os.ReadFile(output)
	require.NoError(t, err)

	var report dependency.Report
	require.NoError(t, json.Unmarshal(raw, &report))

	require.ElementsMatch(t, []string{fileA, fileB}, report.Files)

	var shared dependency.MetricNode
	for _, metric := range report.Metrics {
		if metric.Metric == "shared:metric" {
			shared = metric
		}
	}
	require.Equal(t, "shared:metric", shared.Metric)
	require.True(t, shared.Ambiguous)
	require.Len(t, shared.Producers, 2)
	require.Len(t, shared.Consumers, 2)

	// Both ambiguous producers get a usage report; both see both consumers.
	require.Len(t, report.Usages, 2)
	for _, usage := range report.Usages {
		require.True(t, usage.Ambiguous)
		require.Len(t, usage.DirectUsers, 2)
		var names []string
		for _, edge := range usage.DirectUsers {
			names = append(names, edge.Rule.Name)
			require.True(t, edge.Ambiguous)
		}
		require.ElementsMatch(t, []string{"a:rollup", "SharedHigh"}, names)
	}

	// Regex metric selector is reported as unresolvable and creates no edge.
	require.Len(t, report.UnresolvedReferences, 1)
	require.Equal(t, "dyn:rollup", report.UnresolvedReferences[0].Rule.Name)
	require.Equal(t, dependency.RegexMatchSelector, report.UnresolvedReferences[0].Selectors[0].Type)

	require.Empty(t, report.Cycles)

	// The source files must not be modified.
	contentA, err := os.ReadFile(fileA)
	require.NoError(t, err)
	require.Contains(t, string(contentA), "expr: sum({__name__=~\"foo_.+\"})")
}

func TestRuleCommand_analyzeDependenciesUnknownTarget(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(file, []byte(`
namespace: ns
groups:
  - name: grp
    rules:
      - record: a:one
        expr: up
`), 0o644))

	cmd := &RuleCommand{
		Backend:         rules.MimirBackend,
		logger:          log.NewNopLogger(),
		RuleFilesList:   []string{file},
		DepsRuleTargets: []string{"missing:metric"},
		DepsFormat:      dependenciesFormatJSON,
	}

	err := cmd.analyzeDependencies(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, dependency.ErrUnknownTarget)
}
