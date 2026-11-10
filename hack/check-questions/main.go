// check-questions validates that charts/admission-controller/questions.yaml
// is in sync with charts/admission-controller/values.yaml.
//
// It checks that:
//   - every question (and subquestion) variable path exists in values.yaml
//   - every question default matches the value in values.yaml
//   - every question type is a valid Rancher questions type
//   - every variable referenced in a show_if expression exists in
//     values.yaml or is defined as another question's variable
package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	questionsFile = "charts/admission-controller/questions.yaml"
	valuesFile    = "charts/admission-controller/values.yaml"
)

type question struct {
	Variable     string     `yaml:"variable"`
	Type         string     `yaml:"type"`
	Default      any        `yaml:"default"`
	ShowIf       string     `yaml:"show_if"`
	Subquestions []question `yaml:"subquestions"`
}

type questionsDoc struct {
	Questions []question `yaml:"questions"`
}

func validType(t string) bool {
	if t == "" {
		// Rancher defaults to string
		return true
	}
	// Rancher dashboard: shell/components/Questions
	// Kubewarden UI extension: pkg/kubewarden/components/Questions
	switch t {
	// Rancher and extension
	case "string", "multiline", "boolean", "int", "float", "enum", "password",
		"hostname", "reference", "configmap", "secret", "storageclass", "pvc",
		"cloudcredential":
		return true
	// Rancher only
	case "ipaddr", "cidr", "cron", "radio", "yaml":
		return true
	}
	// Container types matched by prefix, sequence[ is extension only
	containerTypeRe := regexp.MustCompile(`^(array|map|reference|sequence)\[`)
	return containerTypeRe.MatchString(t)
}

// allowedMissingKey reports whether a variable path is allowed to be
// absent from values.yaml: such keys are commented out there (optional
// settings), and the question's default only serves as a Rancher UI
// prefill.
func allowedMissingKey(variable string) bool {
	switch variable {
	case "global.priorityClassName",
		"telemetry.sidecar.tracing.jaeger.endpoint",
		"telemetry.sidecar.tracing.jaeger.tls.insecure":
		return true
	}
	return false
}

// lookup resolves a dotted path in a decoded YAML tree.
func lookup(values map[string]any, path string) (any, bool) {
	var current any = values
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// normalize renders a scalar value in a canonical string form so that
// defaults from questions.yaml can be compared with values.yaml values.
func normalize(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int:
		return strconv.FormatFloat(float64(x), 'f', -1, 64), true
	case int64:
		return strconv.FormatFloat(float64(x), 'f', -1, 64), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	default:
		return "", false // maps, arrays: not compared
	}
}

// flatten returns all questions and subquestions as a single list, plus
// the set of variable names defined by them.
func flatten(qs []question) ([]question, map[string]bool) {
	knownVariables := map[string]bool{}
	var all []question
	var collect func([]question)
	collect = func(qs []question) {
		for _, q := range qs {
			knownVariables[q.Variable] = true
			all = append(all, q)
			collect(q.Subquestions)
		}
	}
	collect(qs)
	return all, knownVariables
}

// checkQuestion validates a single question against values.yaml and
// returns the list of problems found.
func checkQuestion(q question, values map[string]any, knownVariables map[string]bool) []string {
	var errs []string

	val, found := lookup(values, q.Variable)
	if !found && !allowedMissingKey(q.Variable) {
		errs = append(errs, fmt.Sprintf("%s: variable not found in %s", q.Variable, valuesFile))
	}

	if !validType(q.Type) {
		errs = append(errs, fmt.Sprintf("%s: invalid Rancher question type %q", q.Variable, q.Type))
	}

	if q.Default != nil && found {
		defStr, defOK := normalize(q.Default)
		valStr, valOK := normalize(val)
		if defOK && valOK && defStr != valStr {
			errs = append(errs, fmt.Sprintf("%s: default %q does not match values.yaml value %q",
				q.Variable, defStr, valStr))
		}
	}

	showIfVarRe := regexp.MustCompile(`([A-Za-z0-9_.]+)\s*(=|!=)`)
	for _, m := range showIfVarRe.FindAllStringSubmatch(q.ShowIf, -1) {
		ref := m[1]
		if knownVariables[ref] {
			continue
		}
		if _, ok := lookup(values, ref); !ok {
			errs = append(errs, fmt.Sprintf("%s: show_if references unknown variable %q", q.Variable, ref))
		}
	}

	return errs
}

func run() error {
	values := map[string]any{}
	if err := unmarshalFile(valuesFile, &values); err != nil {
		return err
	}
	var doc questionsDoc
	if err := unmarshalFile(questionsFile, &doc); err != nil {
		return err
	}

	all, knownVariables := flatten(doc.Questions)

	var errs []string
	for _, q := range all {
		errs = append(errs, checkQuestion(q, values, knownVariables)...)
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s is out of sync with %s:\n  - %s",
			questionsFile, valuesFile, strings.Join(errs, "\n  - "))
	}
	fmt.Fprintf(os.Stdout, "%s is in sync with %s (%d questions checked)\n",
		questionsFile, valuesFile, len(all))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func unmarshalFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err = yaml.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}
