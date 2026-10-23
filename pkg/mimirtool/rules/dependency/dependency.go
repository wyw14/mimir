// SPDX-License-Identifier: AGPL-3.0-only

// Package dependency builds a static dependency graph between recording and
// alerting rules stored in rule files. It works only on local rule files: it
// never contacts Grafana Mimir and never modifies the input rules.
package dependency

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/grafana/mimir/pkg/mimirtool/rules"
)

const (
	// RecordingKind marks a rule that produces a metric (a recording rule).
	RecordingKind = "recording"
	// AlertingKind marks a rule that produces an alert (an alerting rule).
	AlertingKind = "alerting"

	// RegexMatchSelector is a `__name__=~"pattern"` matcher.
	RegexMatchSelector = "regex_match"
	// RegexNotMatchSelector is a `__name__!~"pattern"` matcher.
	RegexNotMatchSelector = "regex_not_match"
	// NotEqualSelector is a `__name__!="value"` matcher.
	NotEqualSelector = "not_equal"
	// NoMetricNameSelector is a label-only selector without any __name__ matcher,
	// for example `{job="api-server"}`; it can match any metric name.
	NoMetricNameSelector = "no_metric_name"
)

// RuleRef uniquely identifies a single rule in the analyzed set of files.
type RuleRef struct {
	Namespace string `json:"namespace"`
	Group     string `json:"group"`
	RuleIndex int    `json:"rule_index"`
	// Kind is either "recording" or "alerting".
	Kind string `json:"kind"`
	// Name is the recorded metric name or the alerting rule name.
	Name string `json:"name"`
	// Expr is the PromQL expression of the rule, kept verbatim.
	Expr string `json:"expr"`
}

// UnresolvedSelector describes a metric selector whose referenced metric name
// cannot be statically resolved to a single producer.
type UnresolvedSelector struct {
	// Type is one of RegexMatchSelector, RegexNotMatchSelector, NotEqualSelector
	// or NoMetricNameSelector.
	Type string `json:"type"`
	// Name is the label the matcher applies to. It is labels.MetricName when set.
	Name string `json:"name,omitempty"`
	// Value is the literal value or regex pattern of the matcher.
	Value string `json:"value,omitempty"`
}

// MetricNode describes a metric produced by recording rules and the rules that
// reference it through an exact metric name in their PromQL expressions.
type MetricNode struct {
	Metric string `json:"metric"`
	// Ambiguous is true when more than one recording rule produces the metric.
	Ambiguous bool `json:"ambiguous"`
	// Producers are the recording rules whose "record" name equals Metric.
	Producers []RuleRef `json:"producers"`
	// Consumers are the rules whose PromQL expression references Metric with an
	// exact metric name selector. The list is de-duplicated and deterministically
	// ordered.
	Consumers []RuleRef `json:"consumers"`
}

// UnresolvedReference lists the non-statically-resolvable metric selectors found
// in a single rule expression.
type UnresolvedReference struct {
	Rule      RuleRef              `json:"rule"`
	Selectors []UnresolvedSelector `json:"selectors"`
}

// DependencyEdge is a directed dependency from one rule to another: From uses
// the metric produced by To.
type DependencyEdge struct {
	From   RuleRef `json:"from"`
	To     RuleRef `json:"to"`
	Metric string  `json:"metric"`
}

// Cycle reports a set of rules that depend on each other circularly. Edges
// contains only the dependency edges that stay inside the cycle.
type Cycle struct {
	Rules []RuleRef        `json:"rules"`
	Edges []DependencyEdge `json:"edges"`
}

// UsageEdge identifies a rule that uses a target recording rule, either
// directly or indirectly.
type UsageEdge struct {
	Rule RuleRef `json:"rule"`
	// Via lists, in order, the intermediate recorded metric names on the path
	// from the target recording rule to this user. It is empty for direct users.
	Via []string `json:"via,omitempty"`
	// Ambiguous is true when any metric on the path has multiple producers, in
	// which case the dependency cannot be attributed to a single producer.
	Ambiguous bool `json:"ambiguous"`
}

// Usage reports which rules directly or indirectly use a single target
// recording rule.
type Usage struct {
	Target RuleRef `json:"target"`
	// Metric is the metric name produced by the target recording rule.
	Metric string `json:"metric"`
	// Ambiguous is true when the target metric has multiple producers.
	Ambiguous     bool        `json:"ambiguous"`
	DirectUsers   []UsageEdge `json:"direct_users"`
	IndirectUsers []UsageEdge `json:"indirect_users"`
}

// Report is the full result of a static rule dependency analysis. All slices
// are deterministically ordered so that marshaling it produces stable output.
type Report struct {
	Files []string `json:"files"`
	// Rules lists every rule in the analyzed files.
	Rules []RuleRef `json:"rules"`
	// Metrics lists every metric name that is either produced by a recording
	// rule or referenced with an exact name, with its producers and consumers.
	Metrics []MetricNode `json:"metrics"`
	// UnresolvedReferences lists selectors that cannot be statically resolved.
	UnresolvedReferences []UnresolvedReference `json:"unresolved_references"`
	// Cycles lists all circular dependencies between recording rules.
	Cycles []Cycle `json:"cycles"`
	// Usages contains one entry per requested target recording rule.
	Usages []Usage `json:"usages"`
}

// Target selects a recording rule to report usage for. Namespace and Group are
// optional and used to disambiguate recording rules that share a record name.
type Target struct {
	Rule      string
	Namespace string
	Group     string
}

// node is the internal representation of a rule during graph construction.
type node struct {
	ref RuleRef
	// record is the produced metric name for recording rules, empty otherwise.
	record string
	// exactRefs are the de-duplicated exact metric names referenced by the rule.
	exactRefs []string
	// unresolved are the non-statically-resolvable selectors of the rule.
	unresolved []UnresolvedSelector
}

type builder struct {
	nodes     []*node
	producers map[string][]int // metric name -> recording rule IDs (ascending)
	consumers map[string][]int // metric name -> consumer rule IDs (ascending)
}

// Build constructs the dependency graph for the given rule namespaces. files is
// the list of analyzed file paths, echoed back in the report. targets requests
// usage reports for specific recording rules; it may be empty.
//
// Build is read-only: it never accesses the network or rewrites rule files.
func Build(namespaces []rules.RuleNamespace, files []string, targets []Target, promqlParser parser.Parser) (*Report, error) {
	b := &builder{
		producers: map[string][]int{},
		consumers: map[string][]int{},
	}

	if err := b.load(namespaces, promqlParser); err != nil {
		return nil, err
	}

	report := &Report{
		Files:                sortedUniqueStrings(files),
		Rules:                b.ruleRefs(),
		Metrics:              b.metricNodes(),
		UnresolvedReferences: b.unresolvedReferences(),
		Cycles:               b.cycles(),
	}

	usages, err := b.usages(targets)
	if err != nil {
		return nil, err
	}
	report.Usages = usages

	return report, nil
}

func (b *builder) load(namespaces []rules.RuleNamespace, promqlParser parser.Parser) error {
	// Sort namespaces by name so that iteration order does not depend on the
	// map ordering returned by rules.ParseFiles.
	sortedNS := slices.Clone(namespaces)
	sort.Slice(sortedNS, func(i, j int) bool {
		return sortedNS[i].Namespace < sortedNS[j].Namespace
	})

	for _, ns := range sortedNS {
		for groupIdx := range ns.Groups {
			group := &ns.Groups[groupIdx]
			for ruleIdx := range group.Rules {
				rule := &group.Rules[ruleIdx]

				ref := RuleRef{
					Namespace: ns.Namespace,
					Group:     group.Name,
					RuleIndex: ruleIdx,
					Expr:      rule.Expr,
				}

				n := &node{ref: ref}
				if rule.Record != "" {
					n.ref.Kind = RecordingKind
					n.ref.Name = rule.Record
					n.record = rule.Record
				} else {
					n.ref.Kind = AlertingKind
					n.ref.Name = rule.Alert
				}

				expr, err := promqlParser.ParseExpr(rule.Expr)
				if err != nil {
					// ParseFiles already validates every expression, so an error
					// here indicates an internal inconsistency rather than bad input.
					return fmt.Errorf("failed to parse expression for rule %s/%s[%d] (%q): %w",
						ns.Namespace, group.Name, ruleIdx, n.ref.Name, err)
				}

				extractReferences(n, expr)

				id := len(b.nodes)
				b.nodes = append(b.nodes, n)

				if n.record != "" {
					b.producers[n.record] = append(b.producers[n.record], id)
				}
				for _, metric := range n.exactRefs {
					b.consumers[metric] = append(b.consumers[metric], id)
				}
			}
		}
	}
	return nil
}

// extractReferences walks a PromQL expression and records, on n, every exact
// metric name reference and every selector whose metric name is dynamic.
//
// The Prometheus parser only fills VectorSelector.Name for the bare metric
// form (metric_name); the brace form ({__name__="metric_name"}) leaves it
// empty, so exact names are read from the equal __name__ matcher in both
// cases.
func extractReferences(n *node, expr parser.Node) {
	exact := map[string]struct{}{}
	unresolvedByKey := map[string]UnresolvedSelector{}

	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		vs, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}

		hasNameMatcher := false
		for _, matcher := range vs.LabelMatchers {
			if matcher.Name != model.MetricNameLabel {
				continue
			}
			hasNameMatcher = true
			switch matcher.Type {
			case labels.MatchEqual:
				exact[matcher.Value] = struct{}{}
			case labels.MatchRegexp:
				addUnresolved(unresolvedByKey, UnresolvedSelector{Type: RegexMatchSelector, Name: model.MetricNameLabel, Value: matcher.Value})
			case labels.MatchNotRegexp:
				addUnresolved(unresolvedByKey, UnresolvedSelector{Type: RegexNotMatchSelector, Name: model.MetricNameLabel, Value: matcher.Value})
			case labels.MatchNotEqual:
				addUnresolved(unresolvedByKey, UnresolvedSelector{Type: NotEqualSelector, Name: model.MetricNameLabel, Value: matcher.Value})
			}
		}

		if !hasNameMatcher {
			// A label-only selector such as {job="api-server"} can match any
			// metric name and cannot be resolved to a producer.
			addUnresolved(unresolvedByKey, UnresolvedSelector{Type: NoMetricNameSelector})
		}
		return nil
	})

	n.exactRefs = sortedKeySet(exact)
	n.unresolved = make([]UnresolvedSelector, 0, len(unresolvedByKey))
	for _, sel := range unresolvedByKey {
		n.unresolved = append(n.unresolved, sel)
	}
	slices.SortFunc(n.unresolved, func(a, c UnresolvedSelector) int {
		if a.Type != c.Type {
			return compareStrings(a.Type, c.Type)
		}
		if a.Name != c.Name {
			return compareStrings(a.Name, c.Name)
		}
		return compareStrings(a.Value, c.Value)
	})
}

func addUnresolved(set map[string]UnresolvedSelector, sel UnresolvedSelector) {
	set[sel.Type+"\x00"+sel.Name+"\x00"+sel.Value] = sel
}

func (b *builder) ref(id int) RuleRef {
	return b.nodes[id].ref
}

func (b *builder) ruleRefs() []RuleRef {
	refs := make([]RuleRef, 0, len(b.nodes))
	for _, n := range b.nodes {
		refs = append(refs, n.ref)
	}
	// Node IDs are already assigned in (namespace, group order, rule index)
	// order, but sort defensively to guarantee stability.
	sortRuleRefs(refs)
	return refs
}

func (b *builder) metricNodes() []MetricNode {
	names := make(map[string]struct{}, len(b.producers)+len(b.consumers))
	for name := range b.producers {
		names[name] = struct{}{}
	}
	for name := range b.consumers {
		names[name] = struct{}{}
	}

	out := make([]MetricNode, 0, len(names))
	for name := range names {
		node := MetricNode{
			Metric:    name,
			Producers: []RuleRef{},
			Consumers: []RuleRef{},
		}
		for _, id := range b.producers[name] {
			node.Producers = append(node.Producers, b.ref(id))
		}
		for _, id := range b.consumers[name] {
			node.Consumers = append(node.Consumers, b.ref(id))
		}
		node.Ambiguous = len(node.Producers) > 1
		sortRuleRefs(node.Producers)
		sortRuleRefs(node.Consumers)
		out = append(out, node)
	}
	slices.SortFunc(out, func(a, c MetricNode) int { return compareStrings(a.Metric, c.Metric) })
	return out
}

func (b *builder) unresolvedReferences() []UnresolvedReference {
	out := []UnresolvedReference{}
	for _, n := range b.nodes {
		if len(n.unresolved) == 0 {
			continue
		}
		out = append(out, UnresolvedReference{
			Rule:      n.ref,
			Selectors: slices.Clone(n.unresolved),
		})
	}
	sort.Slice(out, func(i, j int) bool { return compareRuleRef(out[i].Rule, out[j].Rule) < 0 })
	return out
}

// dependencyAdj returns a consumer -> producers adjacency list. Edges are
// de-duplicated and target IDs are sorted in ascending order.
func (b *builder) dependencyAdj() map[int][]int {
	adj := make(map[int][]int, len(b.nodes))
	seen := make(map[[2]int]struct{})
	for consumerID, n := range b.nodes {
		for _, metric := range n.exactRefs {
			for _, producerID := range b.producers[metric] {
				key := [2]int{consumerID, producerID}
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				adj[consumerID] = append(adj[consumerID], producerID)
			}
		}
		sort.Ints(adj[consumerID])
	}
	return adj
}

func (b *builder) cycles() []Cycle {
	adj := b.dependencyAdj()

	ids := make([]int, 0, len(b.nodes))
	for id := range b.nodes {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	sccs := tarjanSCC(ids, adj)

	out := []Cycle{}
	for _, memberIDs := range sccs {
		inCycle := len(memberIDs) > 1
		if len(memberIDs) == 1 {
			v := memberIDs[0]
			if slices.Contains(adj[v], v) {
				inCycle = true
			}
		}
		if !inCycle {
			continue
		}

		memberSet := make(map[int]struct{}, len(memberIDs))
		for _, id := range memberIDs {
			memberSet[id] = struct{}{}
		}

		cycle := Cycle{Rules: []RuleRef{}, Edges: []DependencyEdge{}}
		for _, id := range memberIDs {
			cycle.Rules = append(cycle.Rules, b.ref(id))
		}
		for _, from := range memberIDs {
			for _, to := range adj[from] {
				if _, ok := memberSet[to]; !ok {
					continue
				}
				cycle.Edges = append(cycle.Edges, DependencyEdge{
					From:   b.ref(from),
					To:     b.ref(to),
					Metric: b.nodes[to].record,
				})
			}
		}
		sortRuleRefs(cycle.Rules)
		sort.Slice(cycle.Edges, func(i, j int) bool {
			if c := compareRuleRef(cycle.Edges[i].From, cycle.Edges[j].From); c != 0 {
				return c < 0
			}
			if c := compareRuleRef(cycle.Edges[i].To, cycle.Edges[j].To); c != 0 {
				return c < 0
			}
			return cycle.Edges[i].Metric < cycle.Edges[j].Metric
		})
		out = append(out, cycle)
	}

	sort.Slice(out, func(i, j int) bool { return compareRuleRef(out[i].Rules[0], out[j].Rules[0]) < 0 })
	return out
}

func (b *builder) usages(targets []Target) ([]Usage, error) {
	if len(targets) == 0 {
		return []Usage{}, nil
	}

	out := make([]Usage, 0, len(targets))
	for _, target := range targets {
		producerIDs := b.resolveTarget(target)
		if len(producerIDs) == 0 {
			return nil, unknownTargetErr{target: target}
		}
		for _, id := range producerIDs {
			out = append(out, b.usageFor(id))
		}
	}

	sort.Slice(out, func(i, j int) bool { return compareRuleRef(out[i].Target, out[j].Target) < 0 })
	return out, nil
}

func (b *builder) resolveTarget(target Target) []int {
	var matches []int
	for _, id := range b.producers[target.Rule] {
		ref := b.ref(id)
		if target.Namespace != "" && ref.Namespace != target.Namespace {
			continue
		}
		if target.Group != "" && ref.Group != target.Group {
			continue
		}
		matches = append(matches, id)
	}
	sort.Ints(matches)
	return matches
}

func unknownTargetMessage(target Target) string {
	switch {
	case target.Namespace != "" && target.Group != "":
		return fmt.Sprintf("no recording rule named %q found in namespace %q group %q", target.Rule, target.Namespace, target.Group)
	case target.Namespace != "":
		return fmt.Sprintf("no recording rule named %q found in namespace %q", target.Rule, target.Namespace)
	case target.Group != "":
		return fmt.Sprintf("no recording rule named %q found in group %q", target.Rule, target.Group)
	default:
		return fmt.Sprintf("no recording rule named %q found in the analyzed rule files", target.Rule)
	}
}

// usageFor computes the direct and indirect users of the recording rule with
// the given producer ID by traversing producer -> consumer edges in reverse.
func (b *builder) usageFor(targetID int) Usage {
	targetNode := b.nodes[targetID]
	targetMetric := targetNode.record
	targetAmbiguous := len(b.producers[targetMetric]) > 1

	usage := Usage{
		Target:        targetNode.ref,
		Metric:        targetMetric,
		Ambiguous:     targetAmbiguous,
		DirectUsers:   []UsageEdge{},
		IndirectUsers: []UsageEdge{},
	}

	directSet := map[int]struct{}{}
	for _, id := range b.consumers[targetMetric] {
		if id == targetID {
			// Self references are reported as cycles, not as users.
			continue
		}
		directSet[id] = struct{}{}
		usage.DirectUsers = append(usage.DirectUsers, UsageEdge{Rule: b.ref(id), Ambiguous: targetAmbiguous})
	}

	type frontier struct {
		producerID int
		via        []string
		ambiguous  bool
	}

	indirect := map[int]UsageEdge{}
	enqueued := map[int]struct{}{targetID: {}}
	queue := []frontier{{producerID: targetID, via: []string{}, ambiguous: targetAmbiguous}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		metric := b.nodes[cur.producerID].record
		for _, consumerID := range b.consumers[metric] {
			if consumerID == targetID {
				// A back-edge onto the target caused by a cycle is reported as a
				// circular dependency, not as a user of the target.
				continue
			}

			if cur.producerID != targetID {
				if _, isDirect := directSet[consumerID]; !isDirect {
					if _, seen := indirect[consumerID]; !seen {
						indirect[consumerID] = UsageEdge{
							Rule:      b.ref(consumerID),
							Via:       slices.Clone(cur.via),
							Ambiguous: cur.ambiguous,
						}
					}
				}
			}

			// Recording consumers bridge the chain: whoever consumes their output
			// is an indirect user of the target.
			if b.nodes[consumerID].record == "" {
				continue
			}
			if _, ok := enqueued[consumerID]; ok {
				continue
			}
			enqueued[consumerID] = struct{}{}
			nextVia := append(slices.Clone(cur.via), b.nodes[consumerID].record)
			nextAmbiguous := cur.ambiguous || len(b.producers[b.nodes[consumerID].record]) > 1
			queue = append(queue, frontier{producerID: consumerID, via: nextVia, ambiguous: nextAmbiguous})
		}
	}

	for _, edge := range indirect {
		usage.IndirectUsers = append(usage.IndirectUsers, edge)
	}
	sort.Slice(usage.DirectUsers, func(i, j int) bool {
		return compareRuleRef(usage.DirectUsers[i].Rule, usage.DirectUsers[j].Rule) < 0
	})
	sort.Slice(usage.IndirectUsers, func(i, j int) bool {
		return compareRuleRef(usage.IndirectUsers[i].Rule, usage.IndirectUsers[j].Rule) < 0
	})
	return usage
}

// tarjanSCC returns the strongly connected components of the graph using
// Tarjan's algorithm. Singleton SCCs without a self loop are included; callers
// filter them out.
func tarjanSCC(ids []int, adj map[int][]int) [][]int {
	t := &tarjan{
		adj:     adj,
		index:   map[int]int{},
		low:     map[int]int{},
		onStack: map[int]bool{},
	}
	for _, id := range ids {
		if _, visited := t.index[id]; !visited {
			t.strongconnect(id)
		}
	}
	return t.sccs
}

type tarjan struct {
	adj     map[int][]int
	index   map[int]int
	low     map[int]int
	onStack map[int]bool
	stack   []int
	next    int
	sccs    [][]int
}

func (t *tarjan) strongconnect(v int) {
	t.index[v] = t.next
	t.low[v] = t.next
	t.next++
	t.stack = append(t.stack, v)
	t.onStack[v] = true

	for _, w := range t.adj[v] {
		if _, visited := t.index[w]; !visited {
			t.strongconnect(w)
			if t.low[w] < t.low[v] {
				t.low[v] = t.low[w]
			}
		} else if t.onStack[w] {
			if t.index[w] < t.low[v] {
				t.low[v] = t.index[w]
			}
		}
	}

	if t.low[v] == t.index[v] {
		var scc []int
		for {
			w := t.stack[len(t.stack)-1]
			t.stack = t.stack[:len(t.stack)-1]
			t.onStack[w] = false
			scc = append(scc, w)
			if w == v {
				break
			}
		}
		scc = append([]int(nil), scc...)
		t.sccs = append(t.sccs, scc)
	}
}

// ErrUnknownTarget is returned when a requested target does not match any
// recording rule. Callers can use errors.Is to detect missing targets.
var ErrUnknownTarget = errors.New("unknown recording rule target")

type unknownTargetErr struct {
	target Target
}

func (e unknownTargetErr) Error() string { return unknownTargetMessage(e.target) }
func (e unknownTargetErr) Is(target error) bool {
	return target == ErrUnknownTarget
}

func compareStrings(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// compareRuleRef orders rule references by namespace, group and rule index.
func compareRuleRef(a, b RuleRef) int {
	if c := compareStrings(a.Namespace, b.Namespace); c != 0 {
		return c
	}
	if c := compareStrings(a.Group, b.Group); c != 0 {
		return c
	}
	return a.RuleIndex - b.RuleIndex
}

func sortRuleRefs(refs []RuleRef) {
	sort.Slice(refs, func(i, j int) bool { return compareRuleRef(refs[i], refs[j]) < 0 })
}

func sortedKeySet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func sortedUniqueStrings(in []string) []string {
	set := map[string]struct{}{}
	for _, v := range in {
		set[v] = struct{}{}
	}
	return sortedKeySet(set)
}
