package engine

import (
	"context"
	"net/http"
	"sort"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// RuleMethodSwap is the built-in HTTP method swap rule ID.
const RuleMethodSwap = "AD-METHOD-001"

func init() {
	registry[rules.KindMethodSwap] = func(r *rules.Rule) Check { return &methodSwapCheck{rule: r} }
}

// swapCandidates are the methods tried on a path that does not declare them.
var swapCandidates = []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// methodSwapCheck sends the methods a path does not declare, as another
// user with the owner's IDs and as anonymous; a 2xx means the undeclared
// method is served without the authorization of the declared ones.
type methodSwapCheck struct{ rule *rules.Rule }

func (c *methodSwapCheck) Rule() *rules.Rule { return c.rule }

func (c *methodSwapCheck) Phase(spec.Endpoint) int { return 3 }

// declaredMethods returns the sorted methods the inventory declares for
// ep's path (ep's own method included).
func declaredMethods(ep spec.Endpoint, env *Env) []string {
	seen := map[string]bool{ep.Method: true}
	for _, e := range env.Endpoints {
		if e.Path == ep.Path {
			seen[e.Method] = true
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// anchorMethod is the declared method a path's probe runs from, so each path
// is probed once: the lexicographically first non-destructive method, or the
// first method when every declared one is destructive.
func anchorMethod(declared []string) string {
	for _, m := range declared {
		if !isDestructive(m) {
			return m
		}
	}
	return declared[0]
}

// swapMethods are the candidate methods the path does not declare.
func swapMethods(declared []string) []string {
	have := map[string]bool{}
	for _, m := range declared {
		have[m] = true
	}
	var out []string
	for _, m := range swapCandidates {
		if !have[m] {
			out = append(out, m)
		}
	}
	return out
}

func (c *methodSwapCheck) Applies(ep spec.Endpoint, env *Env) bool {
	declared := declaredMethods(ep, env)
	return ep.Method == anchorMethod(declared) && len(swapMethods(declared)) > 0 && ruleApplies(c.rule.Applies, ep, env)
}

// swapActors picks who probes: the other_user of the first owner/other_user
// pair (by name) using the owner's IDs, else any_user with its own IDs; plus
// the anonymous profile. victim is the owner, or nil without one.
func swapActors(ep spec.Endpoint, env *Env) (victim *identity.Profile, attackers []*identity.Profile) {
	pair := &rules.Rule{Steps: []rules.Step{{As: "owner"}, {As: "other_user"}, {As: "anonymous"}}}
	var b binding
	if bs := bindings(pair, ep, env); len(bs) > 0 {
		b = bs[0]
		victim = b["owner"]
		attackers = append(attackers, b["other_user"])
	} else {
		b = bindings(&rules.Rule{Steps: []rules.Step{{As: "any_user"}, {As: "anonymous"}}}, ep, env)[0]
		if p := b["any_user"]; p != nil {
			attackers = append(attackers, p)
		}
	}
	if p := b["anonymous"]; p != nil {
		attackers = append(attackers, p)
	}
	return victim, attackers
}

// swapEndpoint is ep with method m and no declared body; the probe sends "{}".
func swapEndpoint(ep spec.Endpoint, m string) spec.Endpoint {
	e := ep
	e.Method, e.Body = m, nil
	return e
}

// idSourceOf is the profile whose IDs fill the path: the victim, else the attacker.
func idSourceOf(victim, attacker *identity.Profile) string {
	if victim != nil {
		return victim.Name
	}
	return attacker.Name
}

func (c *methodSwapCheck) Plan(ep spec.Endpoint, env *Env) []PlannedRequest {
	victim, attackers := swapActors(ep, env)
	var out []PlannedRequest
	for _, m := range swapMethods(declaredMethods(ep, env)) {
		for _, a := range attackers {
			req, err := env.Builder.Build(swapEndpoint(ep, m), m, idSourceOf(victim, a), nil)
			if err != nil {
				env.logger().Warn("plan: build request", "rule", c.rule.ID, "endpoint", ep.Key(), "err", err)
				continue
			}
			out = append(out, PlannedRequest{RuleID: c.rule.ID, Endpoint: ep.Key(), Step: "swap", Profile: a.Name,
				Method: m, Path: req.Path, Destructive: isDestructive(m)})
		}
	}
	return out
}

func (c *methodSwapCheck) Run(ctx context.Context, ep spec.Endpoint, env *Env) (Outcome, error) {
	var out Outcome
	victim, attackers := swapActors(ep, env)
	victimName := ""
	if victim != nil {
		victimName = victim.Name
	}
	for _, m := range swapMethods(declaredMethods(ep, env)) {
		se := swapEndpoint(ep, m)
		for _, a := range attackers {
			req, err := env.Builder.Build(se, m, idSourceOf(victim, a), nil)
			if err != nil {
				out.Observations = append(out.Observations, buildFailed(env, c.rule.ID, se, m, a.Name, "swap", err))
				continue
			}
			if req.Body == nil {
				req.Body = []byte("{}")
				req.ContentType = "application/json"
				req.Header.Set("Content-Type", req.ContentType)
			}
			// Destructive probes go through the transport: safe mode blocks
			// them and they are recorded as skipped.
			resp, o, err := probe(ctx, env, c.rule.ID, a, "swap", req)
			out.Observations = append(out.Observations, o)
			if err != nil {
				return out, err
			}
			if resp == nil || !isOK(resp.Status) {
				continue
			}
			f := newFinding(c.rule, ep, m, victimName, a.Name, finding.ConfMedium)
			f.Evidence = []finding.Exchange{resp.Exchange}
			out.Findings = append(out.Findings, f)
		}
	}
	return out, nil
}
