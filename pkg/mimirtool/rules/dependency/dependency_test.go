// SPDX-License-Identifier: AGPL-3.0-only

package dependency

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/stretchr/testify/require"

	"github.com/grafana/mimir/pkg/mimirtool/rules"
	"github.com/grafana/mimir/pkg/mimirtool/rules/rwrulefmt"
	"github.com/grafana/mimir/pkg/mimirtool/util"
)

func mkNamespace(name string, groups ...rwrulefmt.RuleGroup) rules.RuleNamespace {
	return rules.RuleNamespace{Namespace: name, Groups: groups}
}

func mkGroup(name string, ruleList ...rulefmt.Rule) rwrulefmt.RuleGroup {
	return rwrulefmt.RuleGroup{RuleGroup: rulefmt.RuleGroup{Name: name, Rules: ruleList}}
}

func mkRecord(name, expr string) rulefmt.Rule {
	return rulefmt.Rule{Record: name, Expr: expr}
}

func mkAlert(name, expr string) rulefmt.Rule {
	return rulefmt.Rule{Alert: name, Expr: expr}
}

func ref(namespace, group string, index int, kind, name string) RuleRef {
	return RuleRef{Namespace: namespace, Group: group, RuleIndex: index, Kind: kind, Name: name}
}

func withExpr(r RuleRef, expr string) RuleRef {
	r.Expr = expr
	return r
}

func metricByName(t *testing.T, report *Report, name string) MetricNode {
	t.Helper()
	for _, metric := range report.Metrics {
		if metric.Metric == name {
			return metric
		}
	}
	require.Failf(t, "metric not found", "metric %q not present in report", name)
	return MetricNode{}
}

func TestBuildGraphAndRuleIdentity(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns1", mkGroup("g1",
			mkRecord("a:ratio", "sum(rate(http_requests_total[5m]))"),
			mkRecord("b:ratio", "a:ratio * 2"),
			mkAlert("HighBRatio", "b:ratio > 1"),
		)),
	}

	report, err := Build(nss, []string{"ns1.yaml"}, nil, util.CreatePromQLParser(false))
	require.NoError(t, err)

	require.Equal(t, []string{"ns1.yaml"}, report.Files)
	require.Equal(t, []RuleRef{
		{Namespace: "ns1", Group: "g1", RuleIndex: 0, Kind: RecordingKind, Name: "a:ratio", Expr: "sum(rate(http_requests_total[5m]))"},
		{Namespace: "ns1", Group: "g1", RuleIndex: 1, Kind: RecordingKind, Name: "b:ratio", Expr: "a:ratio * 2"},
		{Namespace: "ns1", Group: "g1", RuleIndex: 2, Kind: AlertingKind, Name: "HighBRatio", Expr: "b:ratio > 1"},
	}, report.Rules)

	external := metricByName(t, report, "http_requests_total")
	require.False(t, external.Ambiguous)
	require.Empty(t, external.Producers)
	require.Equal(t, []RuleRef{withExpr(ref("ns1", "g1", 0, RecordingKind, "a:ratio"), "sum(rate(http_requests_total[5m]))")}, external.Consumers)

	a := metricByName(t, report, "a:ratio")
	require.Equal(t, []RuleRef{withExpr(ref("ns1", "g1", 0, RecordingKind, "a:ratio"), "sum(rate(http_requests_total[5m]))")}, a.Producers)
	require.Equal(t, []RuleRef{withExpr(ref("ns1", "g1", 1, RecordingKind, "b:ratio"), "a:ratio * 2")}, a.Consumers)

	b := metricByName(t, report, "b:ratio")
	require.Equal(t, []RuleRef{withExpr(ref("ns1", "g1", 1, RecordingKind, "b:ratio"), "a:ratio * 2")}, b.Producers)
	require.Equal(t, []RuleRef{withExpr(ref("ns1", "g1", 2, AlertingKind, "HighBRatio"), "b:ratio > 1")}, b.Consumers)

	require.Empty(t, report.UnresolvedReferences)
	require.Empty(t, report.Cycles)
	require.Empty(t, report.Usages)
}

func TestExplicitEqualMetricNameIsExact(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g",
			mkRecord("exact_metric", "up"),
			mkRecord("c:1", `{__name__="exact_metric"}`),
		)),
	}

	report, err := Build(nss, nil, nil, util.CreatePromQLParser(false))
	require.NoError(t, err)

	node := metricByName(t, report, "exact_metric")
	require.Len(t, node.Producers, 1)
	require.Len(t, node.Consumers, 1)
	require.Equal(t, "c:1", node.Consumers[0].Name)
	require.Empty(t, report.UnresolvedReferences)
}

func TestUnresolvedSelectors(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g",
			mkRecord("r:regex", `sum({__name__=~"foo_.+"})`),
			mkRecord("r:notregex", `count({__name__!~"foo",job="x"})`),
			mkRecord("r:notequal", `count({__name__!="bar",job="x"})`),
			mkRecord("r:labelonly", `count({job="api-server"})`),
			mkRecord("r:dupe", `{__name__=~"foo_.+"} or {__name__=~"foo_.+"}`),
		)),
	}

	report, err := Build(nss, nil, nil, util.CreatePromQLParser(false))
	require.NoError(t, err)

	byRule := map[string][]UnresolvedSelector{}
	for _, u := range report.UnresolvedReferences {
		byRule[u.Rule.Name] = u.Selectors
	}

	require.Equal(t, []UnresolvedSelector{{Type: RegexMatchSelector, Name: "__name__", Value: "foo_.+"}}, byRule["r:regex"])
	require.Equal(t, []UnresolvedSelector{{Type: RegexNotMatchSelector, Name: "__name__", Value: "foo"}}, byRule["r:notregex"])
	require.Equal(t, []UnresolvedSelector{{Type: NotEqualSelector, Name: "__name__", Value: "bar"}}, byRule["r:notequal"])
	require.Equal(t, []UnresolvedSelector{{Type: NoMetricNameSelector}}, byRule["r:labelonly"])

	// Identical dynamic selectors in one rule are de-duplicated.
	require.Len(t, byRule["r:dupe"], 1)

	// Unresolved selectors must not create edges to producers.
	for _, name := range []string{"foo_.+", "foo", "bar"} {
		for _, metric := range report.Metrics {
			require.NotEqual(t, name, metric.Metric)
		}
	}
}

func TestAmbiguousProducers(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("nsA", mkGroup("gA", mkRecord("shared:m", "up"))),
		mkNamespace("nsB", mkGroup("gB", mkRecord("shared:m", "up"))),
		mkNamespace("nsC", mkGroup("gC", mkRecord("c:m", "shared:m"))),
	}

	report, err := Build(nss, nil, nil, util.CreatePromQLParser(false))
	require.NoError(t, err)

	shared := metricByName(t, report, "shared:m")
	require.True(t, shared.Ambiguous)
	require.Len(t, shared.Producers, 2)
	require.Equal(t, "nsA", shared.Producers[0].Namespace)
	require.Equal(t, "nsB", shared.Producers[1].Namespace)
	require.Len(t, shared.Consumers, 1)
	require.Equal(t, "c:m", shared.Consumers[0].Name)

	// No target requested: no usage section.
	require.Empty(t, report.Usages)

	// Targeting the shared record name without filters returns a usage for each
	// producer, each flagged ambiguous.
	report, err = Build(nss, nil, []Target{{Rule: "shared:m"}}, util.CreatePromQLParser(false))
	require.NoError(t, err)
	require.Len(t, report.Usages, 2)
	for _, usage := range report.Usages {
		require.True(t, usage.Ambiguous)
		require.Len(t, usage.DirectUsers, 1)
		require.Equal(t, "c:m", usage.DirectUsers[0].Rule.Name)
		require.True(t, usage.DirectUsers[0].Ambiguous)
	}

	// Namespace filter disambiguates to a single producer.
	report, err = Build(nss, nil, []Target{{Rule: "shared:m", Namespace: "nsB"}}, util.CreatePromQLParser(false))
	require.NoError(t, err)
	require.Len(t, report.Usages, 1)
	require.Equal(t, "nsB", report.Usages[0].Target.Namespace)
}

func TestCycles(t *testing.T) {
	t.Run("two rule cycle", func(t *testing.T) {
		nss := []rules.RuleNamespace{
			mkNamespace("ns", mkGroup("g",
				mkRecord("cyc:a", "cyc:b"),
				mkRecord("cyc:b", "cyc:a"),
				mkRecord("acyclic", "raw"),
			)),
		}

		report, err := Build(nss, nil, nil, util.CreatePromQLParser(false))
		require.NoError(t, err)
		require.Len(t, report.Cycles, 1)

		cycle := report.Cycles[0]
		require.Equal(t, []string{"cyc:a", "cyc:b"}, []string{cycle.Rules[0].Name, cycle.Rules[1].Name})
		require.Len(t, cycle.Edges, 2)

		edges := map[string]string{}
		for _, edge := range cycle.Edges {
			edges[edge.From.Name] = edge.To.Name + "/" + edge.Metric
		}
		require.Equal(t, "cyc:b/cyc:b", edges["cyc:a"])
		require.Equal(t, "cyc:a/cyc:a", edges["cyc:b"])
	})

	t.Run("self loop", func(t *testing.T) {
		nss := []rules.RuleNamespace{
			mkNamespace("ns", mkGroup("g",
				mkRecord("self:a", "self:a + 1"),
			)),
		}

		report, err := Build(nss, nil, nil, util.CreatePromQLParser(false))
		require.NoError(t, err)
		require.Len(t, report.Cycles, 1)
		require.Len(t, report.Cycles[0].Rules, 1)
		require.Equal(t, "self:a", report.Cycles[0].Rules[0].Name)
		require.Len(t, report.Cycles[0].Edges, 1)
		require.Equal(t, "self:a", report.Cycles[0].Edges[0].Metric)

		// The target itself is never listed as its own user; the cycle is the report.
		report, err = Build(nss, nil, []Target{{Rule: "self:a"}}, util.CreatePromQLParser(false))
		require.NoError(t, err)
		require.Empty(t, report.Usages[0].DirectUsers)
		require.Empty(t, report.Usages[0].IndirectUsers)
	})

	t.Run("acyclic graph has no cycles", func(t *testing.T) {
		nss := []rules.RuleNamespace{
			mkNamespace("ns", mkGroup("g",
				mkRecord("a:1", "raw"),
				mkRecord("a:2", "a:1"),
				mkAlert("Alert", "a:2"),
			)),
		}

		report, err := Build(nss, nil, nil, util.CreatePromQLParser(false))
		require.NoError(t, err)
		require.Empty(t, report.Cycles)
	})
}

func TestUsageDirectAndIndirect(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g",
			mkRecord("level0:m", "raw_metric"),
			mkRecord("level1:m", "level0:m"),
			mkRecord("level2:m", "level1:m + other_raw"),
			mkAlert("HighLevel2", "level2:m"),
		)),
	}

	report, err := Build(nss, nil, []Target{{Rule: "level0:m"}}, util.CreatePromQLParser(false))
	require.NoError(t, err)
	require.Len(t, report.Usages, 1)

	usage := report.Usages[0]
	require.Equal(t, "level0:m", usage.Target.Name)
	require.False(t, usage.Ambiguous)

	require.Len(t, usage.DirectUsers, 1)
	require.Equal(t, "level1:m", usage.DirectUsers[0].Rule.Name)
	require.False(t, usage.DirectUsers[0].Ambiguous)
	require.Empty(t, usage.DirectUsers[0].Via)

	require.Len(t, usage.IndirectUsers, 2)
	require.Equal(t, "level2:m", usage.IndirectUsers[0].Rule.Name)
	require.Equal(t, []string{"level1:m"}, usage.IndirectUsers[0].Via)
	require.Equal(t, "HighLevel2", usage.IndirectUsers[1].Rule.Name)
	require.Equal(t, []string{"level1:m", "level2:m"}, usage.IndirectUsers[1].Via)
}

func TestUsageDirectTakesPrecedenceOverIndirect(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g",
			mkRecord("level0:m", "raw"),
			mkRecord("level1:m", "level0:m"),
			// x uses level0 directly and also sits one level above it.
			mkRecord("x:m", "level0:m + level1:m"),
		)),
	}

	report, err := Build(nss, nil, []Target{{Rule: "level0:m"}}, util.CreatePromQLParser(false))
	require.NoError(t, err)
	require.Len(t, report.Usages, 1)

	var direct, indirect []string
	for _, edge := range report.Usages[0].DirectUsers {
		direct = append(direct, edge.Rule.Name)
	}
	for _, edge := range report.Usages[0].IndirectUsers {
		indirect = append(indirect, edge.Rule.Name)
	}
	require.ElementsMatch(t, []string{"level1:m", "x:m"}, direct)
	require.Empty(t, indirect)
}

func TestUsageAmbiguityOnIntermediateMetric(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g",
			mkRecord("root:m", "raw"),
			mkRecord("mid:m", "root:m"),
		)),
		// A second producer makes mid:m ambiguously produced.
		mkNamespace("ns2", mkGroup("g2",
			mkRecord("mid:m", "raw2"),
			mkRecord("leaf:m", "mid:m"),
		)),
	}

	report, err := Build(nss, nil, []Target{{Rule: "root:m", Namespace: "ns"}}, util.CreatePromQLParser(false))
	require.NoError(t, err)
	require.Len(t, report.Usages, 1)

	usage := report.Usages[0]
	require.False(t, usage.Ambiguous)
	require.Len(t, usage.DirectUsers, 1)
	require.False(t, usage.DirectUsers[0].Ambiguous)

	// leaf:m is reached through mid:m which has two producers, so the edge is
	// flagged ambiguous even though the target itself is unambiguous.
	require.Len(t, usage.IndirectUsers, 1)
	require.Equal(t, "leaf:m", usage.IndirectUsers[0].Rule.Name)
	require.True(t, usage.IndirectUsers[0].Ambiguous)
	require.Equal(t, []string{"mid:m"}, usage.IndirectUsers[0].Via)
}

func TestUnknownTarget(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g", mkRecord("a:1", "raw"))),
	}

	_, err := Build(nss, nil, []Target{{Rule: "missing:1"}}, util.CreatePromQLParser(false))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnknownTarget))
}

func TestRenderText(t *testing.T) {
	nss := []rules.RuleNamespace{
		mkNamespace("ns", mkGroup("g",
			mkRecord("a:1", `{__name__=~"x_.*"}`),
			mkRecord("a:2", "a:1"),
		)),
	}

	report, err := Build(nss, nil, []Target{{Rule: "a:1"}}, util.CreatePromQLParser(false))
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, RenderText(&buf, report))

	out := buf.String()
	require.Contains(t, out, "a:1")
	require.Contains(t, out, "cannot statically resolve regex metric selector")
	require.Contains(t, out, "Circular dependencies")
	require.Contains(t, out, "direct users (1):")
	require.Contains(t, out, "a:2")
}

func TestStableJSONOutput(t *testing.T) {
	build := func() []byte {
		nss := []rules.RuleNamespace{
			mkNamespace("zns", mkGroup("g2",
				mkRecord("shared:m", "raw2"),
				mkAlert("AlertZ", "shared:m"),
			)),
			mkNamespace("ans", mkGroup("g1",
				mkRecord("shared:m", "raw1"),
				mkRecord("down:m", "shared:m"),
			)),
		}

		report, err := Build(nss, []string{"b.yaml", "a.yaml", "a.yaml"},
			[]Target{{Rule: "shared:m"}}, util.CreatePromQLParser(false))
		require.NoError(t, err)

		out, err := json.Marshal(report)
		require.NoError(t, err)
		return out
	}

	first := build()
	second := build()
	require.JSONEq(t, string(first), string(second))
	require.Equal(t, string(first), string(second), "byte-for-byte output must be stable")

	var report Report
	require.NoError(t, json.Unmarshal(first, &report))
	require.Equal(t, []string{"a.yaml", "b.yaml"}, report.Files)
	// Namespaces sorted: ans before zns.
	require.Equal(t, "ans", report.Rules[0].Namespace)
}
