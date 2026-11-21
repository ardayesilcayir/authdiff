package rules

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

// StepEnv is the view of an executed step exposed to rule expressions.
type StepEnv struct {
	Sent        bool              `expr:"sent"`
	Status      int               `expr:"status"`
	OK          bool              `expr:"ok"`
	Body        string            `expr:"body"`
	JSON        any               `expr:"json"`
	Profile     string            `expr:"profile"`
	Identifiers []string          `expr:"identifiers"`
	Headers     map[string]string `expr:"headers"`
}

// EndpointEnv is the view of the endpoint under test exposed to expressions.
type EndpointEnv struct {
	Method  string   `expr:"method"`
	Path    string   `expr:"path"`
	Secured bool     `expr:"secured"`
	Admin   bool     `expr:"admin"`
	Tags    []string `expr:"tags"`
}

// Funcs are the helper functions available to rule expressions.
type Funcs struct {
	Similarity    func(a, b string) float64
	Evidence      func(body string, ids []string) bool
	MatrixForbids func(step string) bool
	MatrixAllows  func(step string) bool
}

// withDefaults fills nil helpers with inert implementations.
func (f Funcs) withDefaults() Funcs {
	if f.Similarity == nil {
		f.Similarity = func(a, b string) float64 {
			if a == b {
				return 1
			}
			return 0
		}
	}
	if f.Evidence == nil {
		f.Evidence = func(string, []string) bool { return false }
	}
	if f.MatrixForbids == nil {
		f.MatrixForbids = func(string) bool { return false }
	}
	if f.MatrixAllows == nil {
		f.MatrixAllows = func(string) bool { return false }
	}
	return f
}

// NewEnv builds the expression environment for one evaluation.
// The builtin len() is provided by expr itself and is not added to the map.
func NewEnv(steps map[string]StepEnv, ep EndpointEnv, threshold float64, identifiers []string, fn Funcs) map[string]any {
	fn = fn.withDefaults()
	env := make(map[string]any, len(steps)+7)
	for name, s := range steps {
		env[name] = s
	}
	if ep.Tags == nil {
		ep.Tags = []string{}
	}
	if identifiers == nil {
		identifiers = []string{}
	}
	env["endpoint"] = ep
	env["cfg"] = map[string]any{"similarityThreshold": threshold}
	env["identifiers"] = identifiers
	env["similarity"] = fn.Similarity
	env["evidence"] = fn.Evidence
	env["matrixForbids"] = fn.MatrixForbids
	env["matrixAllows"] = fn.MatrixAllows
	return env
}

// SampleEnv returns an environment with empty values, used for compilation.
func SampleEnv(r *Rule) map[string]any {
	steps := make(map[string]StepEnv, len(r.Steps))
	for _, s := range r.Steps {
		steps[s.Name] = StepEnv{Identifiers: []string{}, Headers: map[string]string{}}
	}
	return NewEnv(steps, EndpointEnv{}, 0, nil, Funcs{})
}

func compile(src string, env map[string]any) (*vm.Program, error) {
	return expr.Compile(src, expr.Env(env), expr.AsBool())
}

func runBool(p *vm.Program, env map[string]any) (bool, error) {
	out, err := expr.Run(p, env)
	if err != nil {
		return false, err
	}
	b, ok := out.(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %T, want bool", out)
	}
	return b, nil
}

// Eval evaluates the rule's match and confidence expressions.
func (r *Rule) Eval(env map[string]any) (bool, finding.Confidence, error) {
	if r.Match == "" {
		if r.kindOrDefault() == KindTemplate {
			return false, "", fmt.Errorf("rule %s: no match expression", r.ID)
		}
		return true, finding.ConfMedium, nil
	}
	if r.match == nil {
		return false, "", fmt.Errorf("rule %s: not validated", r.ID)
	}
	matched, err := runBool(r.match, env)
	if err != nil {
		return false, "", fmt.Errorf("rule %s: match: %w", r.ID, err)
	}
	if !matched {
		return false, "", nil
	}
	levels := []struct {
		p    *vm.Program
		conf finding.Confidence
	}{
		{r.confHigh, finding.ConfHigh},
		{r.confMed, finding.ConfMedium},
		{r.confLow, finding.ConfLow},
	}
	for _, l := range levels {
		if l.p == nil {
			continue
		}
		ok, err := runBool(l.p, env)
		if err != nil {
			return false, "", fmt.Errorf("rule %s: confidence %s: %w", r.ID, l.conf, err)
		}
		if ok {
			return true, l.conf, nil
		}
	}
	return true, finding.ConfMedium, nil
}

// Meta returns the report metadata of the rule.
func (r *Rule) Meta() finding.RuleMeta {
	return finding.RuleMeta{
		ID: r.ID, Name: r.Name, Description: r.Description, OWASP: r.OWASP,
		CWE: r.CWE, Remediation: r.Remediation, Severity: r.Severity, CVSS: r.CVSS,
	}
}
