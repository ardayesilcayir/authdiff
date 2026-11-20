package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/compare"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/planner"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// templateCheck executes a YAML template rule.
type templateCheck struct{ rule *rules.Rule }

func (t *templateCheck) Rule() *rules.Rule { return t.rule }

func (t *templateCheck) Applies(ep spec.Endpoint, env *Env) bool {
	return ruleApplies(t.rule.Applies, ep, env)
}

func (t *templateCheck) Phase(ep spec.Endpoint) int { return methodPhase(ep.Method) }

// ruleApplies evaluates a rule's applies block against ep.
func ruleApplies(a rules.Applies, ep spec.Endpoint, env *Env) bool {
	if len(a.Methods) > 0 {
		ok := false
		for _, m := range a.Methods {
			if strings.EqualFold(m, ep.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if a.PathHasParam != nil && (len(ep.PathParams()) > 0) != *a.PathHasParam {
		return false
	}
	if a.AdminFunction != nil && ep.IsAdminFunction(env.Matrix()) != *a.AdminFunction {
		return false
	}
	if len(a.Paths) > 0 {
		ok := false
		for _, p := range a.Paths {
			if spec.MatchGlob(p, ep.Path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if a.RequiresBody && ep.Body == nil {
		return false
	}
	return true
}

// binding maps each role used by a rule to a profile; singular roles without
// a matching profile map to nil.
type binding map[string]*identity.Profile

// Multi-valued roles, in binding order: other_user is last because it is
// derived from the bound owner (or, without an owner, from self).
var multiRoles = []string{"owner", "low_priv", "self", "other_user"}

func sortedProfiles(ps []*identity.Profile) []*identity.Profile {
	out := append([]*identity.Profile(nil), ps...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// bindings enumerates every role combination for r on ep: the cartesian
// product of the multi-valued roles the rule uses, in profile-name order.
func bindings(r *rules.Rule, ep spec.Endpoint, env *Env) []binding {
	used := map[string]bool{}
	for _, s := range r.Steps {
		used[s.As] = true
		used[s.Use] = true
	}
	ps := sortedProfiles(env.Profiles)
	params := ep.PathParams()

	singles := binding{}
	for _, p := range ps {
		if used["admin"] && singles["admin"] == nil && p.IsAdmin() && !p.IsAnonymous() {
			singles["admin"] = p
		}
		if used["anonymous"] && singles["anonymous"] == nil && p.IsAnonymous() {
			singles["anonymous"] = p
		}
	}
	if used["any_user"] {
		var first, filled *identity.Profile
		for _, p := range ps {
			if p.IsAnonymous() {
				continue
			}
			if first == nil {
				first = p
			}
			if filled == nil && env.Pool.HasAll(p.Name, params) {
				filled = p
			}
		}
		if filled == nil {
			filled = first
		}
		singles["any_user"] = filled
	}

	var multi []string
	for _, role := range multiRoles {
		if used[role] {
			multi = append(multi, role)
		}
	}

	var out []binding
	cur := binding{}
	var rec func(i int)
	rec = func(i int) {
		if i == len(multi) {
			b := binding{}
			for k, v := range singles {
				b[k] = v
			}
			for k, v := range cur {
				b[k] = v
			}
			out = append(out, b)
			return
		}
		role := multi[i]
		for _, p := range ps {
			if p.IsAnonymous() || !candidate(role, p, cur, params, env) {
				continue
			}
			cur[role] = p
			rec(i + 1)
		}
		delete(cur, role)
	}
	rec(0)
	return out
}

// candidate reports whether non-anonymous profile p can fill a multi-valued role.
func candidate(role string, p *identity.Profile, cur binding, params []string, env *Env) bool {
	switch role {
	case "owner":
		return env.Pool.HasAll(p.Name, params)
	case "other_user":
		owner := cur["owner"]
		if owner == nil {
			// No owner in the rule: any other user than the one bound as self.
			self := cur["self"]
			return self == nil || self.Name != p.Name
		}
		return p.Name != owner.Name && p.Role == owner.Role
	case "low_priv":
		return !p.IsAdmin()
	}
	return true // self
}

// stepMethod is the step's method, defaulting to the endpoint's.
func stepMethod(s rules.Step, ep spec.Endpoint) string {
	if s.Method != "" {
		return strings.ToUpper(s.Method)
	}
	return strings.ToUpper(ep.Method)
}

func (t *templateCheck) Plan(ep spec.Endpoint, env *Env) []PlannedRequest {
	var out []PlannedRequest
	for _, b := range bindings(t.rule, ep, env) {
		for _, s := range t.rule.Steps {
			p := b[s.As]
			method := stepMethod(s, ep)
			if p == nil || (s.SkipDestructive && isDestructive(method)) {
				continue
			}
			req, err := env.Builder.Build(ep, method, idSource(s, b), s.Body)
			if err != nil {
				env.logger().Warn("plan: build request", "rule", t.rule.ID, "endpoint", ep.Key(), "err", err)
				continue
			}
			n := s.Repeat
			if n < 1 {
				n = 1
			}
			for i := 0; i < n; i++ {
				out = append(out, PlannedRequest{
					RuleID: t.rule.ID, Endpoint: ep.Key(), Step: s.Name, Profile: p.Name,
					Method: method, Path: req.Path, Destructive: isDestructive(method),
				})
			}
		}
	}
	return out
}

func (t *templateCheck) Run(ctx context.Context, ep spec.Endpoint, env *Env) (Outcome, error) {
	var out Outcome
	for _, b := range bindings(t.rule, ep, env) {
		f, obs, err := t.runBinding(ctx, ep, env, b)
		out.Observations = append(out.Observations, obs...)
		if err != nil {
			return out, err
		}
		if f != nil {
			out.Findings = append(out.Findings, *f)
		}
	}
	return out, nil
}

// stepResult is the outcome of one executed step.
type stepResult struct {
	profile *identity.Profile
	req     planner.Request
	built   bool
	resp    *transport.Response // nil unless sent
}

// runBinding executes the rule's steps for one role combination, evaluates
// the match and returns a finding when it matched.
func (t *templateCheck) runBinding(ctx context.Context, ep spec.Endpoint, env *Env, b binding) (*finding.Finding, []Observation, error) {
	r := t.rule
	results := make(map[string]*stepResult, len(r.Steps))
	dyn := map[string]bool{}
	var obs []Observation

	for _, s := range r.Steps {
		sr := &stepResult{profile: b[s.As]}
		results[s.Name] = sr
		if sr.profile == nil {
			continue
		}
		method := stepMethod(s, ep)
		req, err := env.Builder.Build(ep, method, idSource(s, b), s.Body)
		if err != nil {
			return nil, obs, fmt.Errorf("rule %s step %s: %w", r.ID, s.Name, err)
		}
		sr.req, sr.built = req, true
		o := Observation{Endpoint: method + " " + ep.Path, Profile: sr.profile.Name, OwnIDs: req.OwnedBy(sr.profile.Name)}
		if s.SkipDestructive && isDestructive(method) {
			obs = append(obs, o)
			continue
		}
		resp, err := env.Sender.Send(ctx, sr.profile, s.Name, req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, obs, ctx.Err()
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, obs, err
			}
			if !errors.Is(err, transport.ErrDestructiveBlocked) && !errors.Is(err, transport.ErrOutOfScope) {
				o.Err = err.Error()
				env.logger().Debug("request failed", "rule", r.ID, "step", s.Name, "err", err)
			}
			obs = append(obs, o)
			continue
		}
		sr.resp = resp
		o.Sent, o.Status = true, resp.Status
		obs = append(obs, o)
		if err := sendRepeats(ctx, env, sr.profile, s, req, resp, dyn); err != nil {
			return nil, obs, err
		}
	}

	sim := func(a, b string) float64 {
		return compare.Similarity([]byte(a), []byte(b), compare.Options{IgnoreFields: env.Config.Compare.IgnoreFields, Dynamic: dyn})
	}
	steps := make(map[string]rules.StepEnv, len(results))
	for name, sr := range results {
		steps[name] = stepEnv(sr)
	}
	vm := rules.NewEnv(steps, rules.EndpointEnv{
		Method: ep.Method, Path: ep.Path, Secured: ep.Secured, Admin: ep.IsAdminFunction(env.Matrix()), Tags: ep.Tags,
	}, env.threshold(), allIdentifiers(env.Profiles), rules.Funcs{
		Similarity: sim,
		Evidence: func(body string, ids []string) bool {
			ok, _ := compare.Evidence([]byte(body), ids)
			return ok
		},
		MatrixForbids: func(step string) bool { return matrixForbids(env, ep, results[step]) },
	})
	matched, conf, err := r.Eval(vm)
	if err != nil {
		return nil, obs, err
	}
	if !matched {
		return nil, obs, nil
	}

	victim, attacker := results[r.Victim], results[r.Attacker]
	f := finding.Finding{
		ID:          finding.NewID(r.ID, ep.Method, ep.Path, profileName(victim), profileName(attacker)),
		RuleID:      r.ID,
		Title:       r.Name,
		Description: strings.TrimSpace(r.Description),
		OWASP:       r.OWASP,
		CWE:         r.CWE,
		Severity:    r.Severity,
		CVSS:        r.CVSS,
		Confidence:  conf,
		Method:      ep.Method,
		Path:        ep.Path,
		Line:        ep.Line,
		Victim:      profileName(victim),
		Attacker:    profileName(attacker),
		Similarity:  sim(stepEnv(victim).Body, stepEnv(attacker).Body),
		Remediation: r.Remediation,
	}
	for _, s := range r.Steps {
		if sr := results[s.Name]; sr.resp != nil {
			f.Evidence = append(f.Evidence, sr.resp.Exchange)
		}
	}
	return &f, obs, nil
}

func profileName(sr *stepResult) string {
	if sr == nil || sr.profile == nil {
		return ""
	}
	return sr.profile.Name
}

// stepEnv exposes a step result to rule expressions.
func stepEnv(sr *stepResult) rules.StepEnv {
	e := rules.StepEnv{Identifiers: []string{}, Headers: map[string]string{}}
	if sr == nil {
		return e
	}
	if sr.profile != nil {
		e.Profile = sr.profile.Name
		if sr.profile.Identifiers != nil {
			e.Identifiers = sr.profile.Identifiers
		}
	}
	if sr.resp == nil {
		return e
	}
	e.Sent = true
	e.Status = sr.resp.Status
	e.OK = sr.resp.Status >= 200 && sr.resp.Status < 300
	e.Body = string(sr.resp.Body)
	var v any
	if json.Unmarshal(sr.resp.Body, &v) == nil {
		e.JSON = v
	}
	for k, vs := range sr.resp.Header {
		if len(vs) > 0 {
			e.Headers[strings.ToLower(k)] = vs[0]
		}
	}
	return e
}

// matrixForbids reports whether the configured matrix forbids the step's
// profile on ep. The profile is allowed when its name or role is listed, or
// when "owner" is listed and the request addressed the profile's own objects.
// Without a matching matrix rule (or an unbound step) nothing is forbidden.
func matrixForbids(env *Env, ep spec.Endpoint, sr *stepResult) bool {
	if sr == nil || sr.profile == nil {
		return false
	}
	allow, ok := env.matrixAllow(ep)
	if !ok {
		return false
	}
	p := sr.profile
	for _, a := range allow {
		if strings.EqualFold(a, p.Name) || strings.EqualFold(a, p.Role) {
			return false
		}
		if strings.EqualFold(a, "owner") && sr.built && sr.req.OwnedBy(p.Name) {
			return false
		}
	}
	return true
}
