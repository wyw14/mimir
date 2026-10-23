// SPDX-License-Identifier: AGPL-3.0-only

package dependency

import (
	"fmt"
	"io"
	"strings"
)

// RenderText writes a human-readable summary of the dependency report to w.
// The JSON form of Report is the stable machine-readable output; this renderer
// is intended for interactive use.
func RenderText(w io.Writer, report *Report) error {
	var b strings.Builder

	fmt.Fprintf(&b, "Analyzed %d rule file(s): %s\n", len(report.Files), strings.Join(report.Files, ", "))
	fmt.Fprintf(&b, "Rules: %d | Produced/referenced metrics: %d | Unresolvable selector groups: %d | Circular dependencies: %d\n\n",
		len(report.Rules), len(report.Metrics), len(report.UnresolvedReferences), len(report.Cycles))

	b.WriteString("Metrics\n")
	if len(report.Metrics) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, metric := range report.Metrics {
		if metric.Ambiguous {
			fmt.Fprintf(&b, "  %s [AMBIGUOUS: %d producers]\n", metric.Metric, len(metric.Producers))
		} else {
			fmt.Fprintf(&b, "  %s\n", metric.Metric)
		}
		for _, producer := range metric.Producers {
			fmt.Fprintf(&b, "    produced by %s\n", formatRuleRef(producer))
		}
		if len(metric.Producers) == 0 {
			b.WriteString("    produced by (no recording rule; external metric)\n")
		}
		for _, consumer := range metric.Consumers {
			fmt.Fprintf(&b, "    used by     %s\n", formatRuleRef(consumer))
		}
	}

	b.WriteString("\nUnresolvable metric selectors\n")
	if len(report.UnresolvedReferences) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, ref := range report.UnresolvedReferences {
		fmt.Fprintf(&b, "  %s\n", formatRuleRef(ref.Rule))
		for _, sel := range ref.Selectors {
			fmt.Fprintf(&b, "    %s\n", formatSelector(sel))
		}
	}

	b.WriteString("\nCircular dependencies\n")
	if len(report.Cycles) == 0 {
		b.WriteString("  (none)\n")
	}
	for i, cycle := range report.Cycles {
		fmt.Fprintf(&b, "  cycle #%d:\n", i+1)
		for _, rule := range cycle.Rules {
			fmt.Fprintf(&b, "    %s\n", formatRuleRef(rule))
		}
		for _, edge := range cycle.Edges {
			fmt.Fprintf(&b, "    %s -> %s (via %s)\n", formatRuleRef(edge.From), formatRuleRef(edge.To), edge.Metric)
		}
	}

	if len(report.Usages) > 0 {
		b.WriteString("\nUsage\n")
		for _, usage := range report.Usages {
			ambiguous := ""
			if usage.Ambiguous {
				ambiguous = " [TARGET METRIC IS AMBIGUOUSLY PRODUCED]"
			}
			fmt.Fprintf(&b, "  %s (%s)%s\n", formatRuleRef(usage.Target), usage.Metric, ambiguous)

			fmt.Fprintf(&b, "    direct users (%d):\n", len(usage.DirectUsers))
			for _, edge := range usage.DirectUsers {
				fmt.Fprintf(&b, "      %s%s\n", formatRuleRef(edge.Rule), ambiguousSuffix(edge.Ambiguous))
			}
			fmt.Fprintf(&b, "    indirect users (%d):\n", len(usage.IndirectUsers))
			for _, edge := range usage.IndirectUsers {
				via := ""
				if len(edge.Via) > 0 {
					via = " (via " + strings.Join(edge.Via, " -> ") + ")"
				}
				fmt.Fprintf(&b, "      %s%s%s\n", formatRuleRef(edge.Rule), via, ambiguousSuffix(edge.Ambiguous))
			}
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func formatRuleRef(ref RuleRef) string {
	return fmt.Sprintf("%s/%s[%d] %s (%s)", ref.Namespace, ref.Group, ref.RuleIndex, ref.Name, ref.Kind)
}

func formatSelector(sel UnresolvedSelector) string {
	switch sel.Type {
	case RegexMatchSelector:
		return fmt.Sprintf("%s=~%q (cannot statically resolve regex metric selector)", sel.Name, sel.Value)
	case RegexNotMatchSelector:
		return fmt.Sprintf("%s!~%q (cannot statically resolve negated regex metric selector)", sel.Name, sel.Value)
	case NotEqualSelector:
		return fmt.Sprintf("%s!=%q (cannot statically resolve negated metric selector)", sel.Name, sel.Value)
	case NoMetricNameSelector:
		return "no __name__ matcher (label-only selector can match any metric)"
	default:
		return sel.Type
	}
}

func ambiguousSuffix(ambiguous bool) string {
	if ambiguous {
		return " [ambiguous producer on path]"
	}
	return ""
}
