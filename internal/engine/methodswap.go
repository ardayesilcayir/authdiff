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
	return ep.Method == anchorMethod(declared) && len(probeMethods(ep, env)) > 0 && ruleApplies(c.rule.Applies, ep, env)
}

// swapActors picks who probes: the other_user of the first owner/other_user
// pair (by name) whose other_user is not an admin, using the owner's IDs;
// else the first non-admin user (preferring one that owns every path
// parameter) with its own IDs; plus the anonymous profile. An admin profile
// is never an attacker: an admin is expected to be allowed, and a destructive
// probe as admin would really change data. victim is the owner, or nil.
func swapActors(ep spec.Endpoint, env *Env) (victim *identity.Profile, attackers []*identity.Profile) {
	pair := &rules.Rule{Steps: []rules.Step{{As: "owner"}, {As: "other_user"}}}
	for _, b := range bindings(pair, ep, env) {
		if a := b["other_user"]; a != nil && !a.IsAdmin() {
			victim = b["owner"]
			attackers = append(attackers, a)
			break
		}
	}
	if len(attackers) == 0 {
		if p := nonAdminUser(ep, env); p != nil {
			attackers = append(attackers, p)
		}
	}
	for _, p := range sortedProfiles(env.Profiles) {
		if p.IsAnonymous() {
			attackers = append(attackers, p)
			break
		}
	}
	return victim, attackers
}

// nonAdminUser is the first non-anonymous, non-admin profile by name that
// owns every path parameter of ep, else the first such profile; nil when
// there is none.
func nonAdminUser(ep spec.Endpoint, env *Env) *identity.Profile {
	params := ep.PathParams()
	var first *identity.Profile
	for _, p := range sortedProfiles(env.Profiles) {
		if p.IsAnonymous() || p.IsAdmin() {
			continue
		}
		if env.Pool.HasAll(p.Name, params) {
			return p
		}
		if first == nil {
			first = p
		}
	}
	return first
}

// probeMethods are the swap methods sent on ep's path: destructive methods
// are never sent to a path without path parameters, since a collection-level
// PUT/PATCH/DELETE could replace or wipe every object.
func probeMethods(ep spec.Endpoint, env *Env) []string {
	ms := swapMethods(declaredMethods(ep, env))
	if len(ep.PathParams()) > 0 {
		return ms
	}
	out := ms[:0:0]
	for _, m := range ms {
		if !isDestructive(m) {
			out = append(out, m)
		}
	}
	return out
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
	for _, m := range probeMethods(ep, env) {
		for _, a := range attackers {
			req, err := env.Builder.Build(swapEndpoint(ep, m), m, idSourceOf(victim, a), nil)
			if err != nil {
				env.logger().Warn("plan: build request", "rule", c.rule.ID, "endpoint", ep.Key(), "err", err)
				continue
			}
			if unownedDestructive(req) {
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
	for _, m := range probeMethods(ep, env) {
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
