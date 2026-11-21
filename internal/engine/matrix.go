package engine

import (
	"context"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// RuleMatrix is the built-in authorization matrix rule ID.
const RuleMatrix = "AD-MATRIX-001"

// matrixVictim is the victim name of matrix findings: the declared policy.
const matrixVictim = "matrix"

func init() {
	registry[rules.KindMatrix] = func(r *rules.Rule) Check { return &matrixCheck{rule: r} }
}

// matrixCheck never runs per endpoint; Run evaluates it with EvaluateMatrix
// over every observation once all phases are done.
type matrixCheck struct{ rule *rules.Rule }

func (c *matrixCheck) Rule() *rules.Rule                         { return c.rule }
func (c *matrixCheck) Applies(spec.Endpoint, *Env) bool          { return false }
func (c *matrixCheck) Phase(spec.Endpoint) int                   { return 0 }
func (c *matrixCheck) Plan(spec.Endpoint, *Env) []PlannedRequest { return nil }
func (c *matrixCheck) Run(context.Context, spec.Endpoint, *Env) (Outcome, error) {
	return Outcome{}, nil
}

// EvaluateMatrix reports every profile that got a 2xx on an endpoint whose
// matching matrix rules do not allow it by name, by role, or as "owner" when
// the request addressed the profile's own IDs. A method+path+attacker that
// already has a finding in existing (or earlier in the result) is not
// reported again. Findings carry no source line; Run fills it in.
func EvaluateMatrix(cfg *config.Config, obs []Observation, existing []finding.Finding, rule *rules.Rule) []finding.Finding {
	m := matrixOf(cfg)
	if len(m) == 0 || rule == nil {
		return nil
	}
	seen := map[string]bool{}
	key := func(method, path, attacker string) string { return method + " " + path + "|" + attacker }
	for _, f := range existing {
		seen[key(f.Method, f.Path, f.Attacker)] = true
	}
	var out []finding.Finding
	for _, o := range obs {
		if !o.Sent || !isOK(o.Status) || o.Profile == "" {
			continue
		}
		method, path, ok := strings.Cut(o.Endpoint, " ")
		if !ok || method == "" || path == "" {
			continue
		}
		k := key(method, path, o.Profile)
		if seen[k] {
			continue
		}
		ep := spec.Endpoint{Method: method, Path: path}
		allow, matched := matrixAllowOf(m, ep)
		if !matched || matrixAllows(allow, o.Profile, cfg.Profiles[o.Profile].Role, o.OwnIDs) {
			continue
		}
		seen[k] = true
		f := newFinding(rule, ep, method, matrixVictim, o.Profile, finding.ConfHigh)
		f.Description += "\n\nAllowed by the matrix: " + strings.Join(allow, ", ") + "."
		if o.Exchange != nil {
			f.Evidence = []finding.Exchange{*o.Exchange}
		}
		out = append(out, f)
	}
	return out
}

// matrixAllows reports whether an allow list admits a profile.
func matrixAllows(allow []string, name, role string, ownIDs bool) bool {
	for _, a := range allow {
		if strings.EqualFold(a, name) || (role != "" && strings.EqualFold(a, role)) {
			return true
		}
		if strings.EqualFold(a, "owner") && ownIDs {
			return true
		}
	}
	return false
}
