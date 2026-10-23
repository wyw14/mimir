// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/common/model"

	"github.com/grafana/mimir/pkg/mimirtool/rules"
	"github.com/grafana/mimir/pkg/mimirtool/rules/dependency"
	"github.com/grafana/mimir/pkg/mimirtool/util"
)

const (
	dependenciesFormatText = "text"
	dependenciesFormatJSON = "json"
)

var dependenciesFormats = []string{dependenciesFormatText, dependenciesFormatJSON}

func (r *RuleCommand) analyzeDependencies(_ *kingpin.ParseContext) error {
	if err := r.setupArgs(); err != nil {
		return errors.Wrap(err, "dependencies operation unsuccessful, invalid arguments")
	}

	// Rule files may be provided both positionally and through --rule-dirs;
	// de-duplicate so namespaces are not parsed twice.
	ruleFiles := slices.Clone(r.RuleFilesList)
	slices.Sort(ruleFiles)
	ruleFiles = slices.Compact(ruleFiles)

	promqlParser := util.CreatePromQLParser(r.enableExperimentalFunctions)

	namespacesByFile, err := rules.ParseFiles(r.Backend, ruleFiles, model.LegacyValidation, promqlParser, r.logger)
	if err != nil {
		return errors.Wrap(err, "dependencies operation unsuccessful, unable to parse rules files")
	}

	namespaces := make([]rules.RuleNamespace, 0, len(namespacesByFile))
	for _, ns := range namespacesByFile {
		namespaces = append(namespaces, ns)
	}

	targets := make([]dependency.Target, 0, len(r.DepsRuleTargets))
	for _, target := range r.DepsRuleTargets {
		targets = append(targets, dependency.Target{
			Rule:      target,
			Namespace: r.DepsNamespace,
			Group:     r.DepsGroup,
		})
	}

	report, err := dependency.Build(namespaces, ruleFiles, targets, promqlParser)
	if err != nil {
		return errors.Wrap(err, "dependencies operation unsuccessful")
	}

	out, err := renderDependencies(report, r.DepsFormat)
	if err != nil {
		return err
	}

	if r.DepsOutputFile != "" {
		if err := os.WriteFile(r.DepsOutputFile, out, 0o666); err != nil {
			return errors.Wrap(err, "dependencies operation unsuccessful, unable to write output file")
		}
		level.Info(r.logger).Log("msg", "dependency report written", "file", r.DepsOutputFile)
		return nil
	}

	_, err = os.Stdout.Write(out)
	return err
}

func renderDependencies(report *dependency.Report, format string) ([]byte, error) {
	switch format {
	case dependenciesFormatJSON:
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return nil, errors.Wrap(err, "dependencies operation unsuccessful, unable to encode report as JSON")
		}
		return append(out, '\n'), nil
	case dependenciesFormatText, "":
		var buf bytes.Buffer
		if err := dependency.RenderText(&buf, report); err != nil {
			return nil, errors.Wrap(err, "dependencies operation unsuccessful, unable to render report")
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}
