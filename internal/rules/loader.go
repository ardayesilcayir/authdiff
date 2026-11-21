// Package rules loads, validates and evaluates YAML rule templates.
package rules

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	rulesfs "github.com/ardayesilcayir/authdiff/rules"
)

// Rule kinds.
const (
	KindTemplate   = "template"
	KindMassAssign = "massassign"
	KindMethodSwap = "methodswap"
	KindLeak       = "leak"
	KindMatrix     = "matrix"
)

// Roles are the valid values for a step's As and Use fields.
var Roles = []string{"owner", "other_user", "low_priv", "admin", "anonymous", "any_user", "self"}

var (
	idRe       = regexp.MustCompile(`^[A-Z]+(-[A-Z0-9]+)+$`)
	stepNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

// Applies restricts the endpoints a rule runs against.
type Applies struct {
	Methods       []string `yaml:"methods"`
	PathHasParam  *bool    `yaml:"pathHasParam"`
	AdminFunction *bool    `yaml:"adminFunction"`
	Paths         []string `yaml:"paths"`
	RequiresBody  bool     `yaml:"requiresBody"`
}

// Step is one request a template rule asks the engine to send.
type Step struct {
	Name            string         `yaml:"name"`
	As              string         `yaml:"as"`
	Use             string         `yaml:"use"`
	Method          string         `yaml:"method"`
	Repeat          int            `yaml:"repeat"`
	SkipDestructive bool           `yaml:"skipDestructive"`
	Body            map[string]any `yaml:"body"`
}

// ConfidenceExprs are optional expressions deciding finding confidence.
type ConfidenceExprs struct {
	High   string `yaml:"high"`
	Medium string `yaml:"medium"`
	Low    string `yaml:"low"`
}

// Rule is a validated rule template.
type Rule struct {
	ID          string           `yaml:"id"`
	Name        string           `yaml:"name"`
	OWASP       string           `yaml:"owasp"`
	CWE         string           `yaml:"cwe"`
	Description string           `yaml:"description"`
	Remediation string           `yaml:"remediation"`
	Kind        string           `yaml:"kind"`
	Match       string           `yaml:"match"`
	Victim      string           `yaml:"victim"`
	Attacker    string           `yaml:"attacker"`
	Source      string           `yaml:"-"`
	Severity    finding.Severity `yaml:"severity"`
	CVSS        float64          `yaml:"cvss"`
	Applies     Applies          `yaml:"applies"`
	Steps       []Step           `yaml:"steps"`
	Confidence  ConfidenceExprs  `yaml:"confidence"`

	match, confHigh, confMed, confLow *vm.Program
}

func (r *Rule) kindOrDefault() string {
	if r.Kind == "" {
		return KindTemplate
	}
	return r.Kind
}

func normalizeRole(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{{"), "}}")
	s = strings.TrimSpace(s)
	return strings.TrimSuffix(s, ".owns")
}

func inRoles(s string) bool {
	for _, r := range Roles {
		if r == s {
			return true
		}
	}
	return false
}

var reservedNames = map[string]bool{
	"endpoint": true, "cfg": true, "identifiers": true,
	"similarity": true, "evidence": true, "matrixForbids": true, "matrixAllows": true, "len": true,
}

// MaxRepeat is the largest accepted step repeat count.
const MaxRepeat = 10

// Validate checks the rule, fills defaults and compiles its expressions.
// Errors name the offending field.
func Validate(r *Rule) error {
	if !idRe.MatchString(r.ID) {
		return fmt.Errorf("id: %q does not match %s", r.ID, idRe)
	}
	sev, err := finding.ParseSeverity(string(r.Severity))
	if err != nil {
		return fmt.Errorf("severity: %w", err)
	}
	r.Severity = sev
	if r.CVSS == 0 {
		r.CVSS = finding.DefaultCVSS(sev)
	}
	switch r.Kind {
	case "":
		r.Kind = KindTemplate
	case KindTemplate, KindMassAssign, KindMethodSwap, KindLeak, KindMatrix:
	default:
		return fmt.Errorf("kind: unknown kind %q", r.Kind)
	}
	if r.Kind == KindTemplate {
		if len(r.Steps) == 0 {
			return fmt.Errorf("steps: template rule needs at least one step")
		}
		if strings.TrimSpace(r.Match) == "" {
			return fmt.Errorf("match: template rule needs a match expression")
		}
	}
	seen := map[string]bool{}
	for i := range r.Steps {
		s := &r.Steps[i]
		s.As = normalizeRole(s.As)
		s.Use = normalizeRole(s.Use)
		if !stepNameRe.MatchString(s.Name) {
			return fmt.Errorf("steps[%d].name: %q must match %s", i, s.Name, stepNameRe)
		}
		if seen[s.Name] || reservedNames[s.Name] {
			return fmt.Errorf("steps[%d].name: duplicate or reserved step name %q", i, s.Name)
		}
		seen[s.Name] = true
		if !inRoles(s.As) {
			return fmt.Errorf("steps[%d].as: unknown role %q", i, s.As)
		}
		if !inRoles(s.Use) {
			return fmt.Errorf("steps[%d].use: unknown role %q", i, s.Use)
		}
		if s.Repeat < 0 || s.Repeat > MaxRepeat {
			return fmt.Errorf("steps[%d].repeat: must be between 0 and %d, got %d", i, MaxRepeat, s.Repeat)
		}
	}
	if r.Kind == KindTemplate {
		if r.Victim == "" {
			r.Victim = r.Steps[0].Name
		}
		if r.Attacker == "" {
			r.Attacker = r.Steps[len(r.Steps)-1].Name
		}
		if !seen[r.Victim] {
			return fmt.Errorf("victim: %q is not a step name", r.Victim)
		}
		if !seen[r.Attacker] {
			return fmt.Errorf("attacker: %q is not a step name", r.Attacker)
		}
	}
	env := SampleEnv(r)
	for _, f := range []struct {
		field string
		src   string
		dst   **vm.Program
	}{
		{"match", r.Match, &r.match},
		{"confidence.high", r.Confidence.High, &r.confHigh},
		{"confidence.medium", r.Confidence.Medium, &r.confMed},
		{"confidence.low", r.Confidence.Low, &r.confLow},
	} {
		if strings.TrimSpace(f.src) == "" {
			*f.dst = nil
			continue
		}
		p, err := compile(f.src, env)
		if err != nil {
			return fmt.Errorf("%s: %w", f.field, err)
		}
		*f.dst = p
	}
	return nil
}

func parse(data []byte, source string) (Rule, error) {
	var r Rule
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return Rule{}, fmt.Errorf("%s: parse yaml: %w", source, err)
	}
	r.Source = source
	if err := Validate(&r); err != nil {
		return Rule{}, fmt.Errorf("%s: %w", source, err)
	}
	return r, nil
}

// LoadFile loads and validates one rule file.
func LoadFile(path string) (Rule, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: rule path is operator-supplied
	if err != nil {
		return Rule{}, fmt.Errorf("read rule %s: %w", path, err)
	}
	return parse(data, path)
}

// LoadDir loads every *.yaml / *.yml file in dir, sorted by file name.
func LoadDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var out []Rule
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		r, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// LoadBuiltin loads the rules embedded in the binary.
func LoadBuiltin() ([]Rule, error) {
	names, err := fs.Glob(rulesfs.FS, "*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]Rule, 0, len(names))
	for _, n := range names {
		data, err := rulesfs.FS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		r, err := parse(data, "builtin/"+n)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
