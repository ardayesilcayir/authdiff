package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/compare"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// RuleMass is the built-in mass assignment rule ID.
const RuleMass = "AD-MASS-001"

func init() {
	registry[rules.KindMassAssign] = func(r *rules.Rule) Check { return &massAssignCheck{rule: r} }
}

// massFields are the server-controlled properties a mass assignment probe
// injects, in injection order.
var massFields = []string{"role", "isAdmin", "is_admin", "ownerId"}

// fallbackOwnerID is injected as ownerId when no other profile has a userId.
const fallbackOwnerID = 999999

// massAssignCheck writes each profile's own object with privileged fields
// added and reads it back with the GET of the same path: a field that now
// carries the injected value (and did not before) was bound by the server.
type massAssignCheck struct{ rule *rules.Rule }

func (c *massAssignCheck) Rule() *rules.Rule { return c.rule }

func (c *massAssignCheck) Phase(spec.Endpoint) int { return 2 }

func (c *massAssignCheck) Applies(ep spec.Endpoint, env *Env) bool {
	switch ep.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	if ep.Body == nil || !isJSONType(ep.Body.ContentType) || !ruleApplies(c.rule.Applies, ep, env) {
		return false
	}
	_, ok := sameGET(ep, env)
	return ok
}

// isJSONType reports whether a request body content type is JSON (an empty
// type defaults to JSON in the planner).
func isJSONType(ct string) bool {
	return ct == "" || strings.Contains(strings.ToLower(ct), "json")
}

// sameGET returns the inventory's GET endpoint with ep's path template.
func sameGET(ep spec.Endpoint, env *Env) (spec.Endpoint, bool) {
	for _, e := range env.Endpoints {
		if e.Method == http.MethodGet && e.Path == ep.Path {
			return e, true
		}
	}
	return spec.Endpoint{}, false
}

// injectedFields are the massFields not declared in ep's request body,
// with the values injected for profile self.
func injectedFields(ep spec.Endpoint, env *Env, self string) map[string]any {
	declared := map[string]bool{}
	for _, f := range ep.Body.Fields {
		declared[f] = true
	}
	out := map[string]any{}
	for _, f := range massFields {
		if declared[f] {
			continue
		}
		switch f {
		case "role":
			out[f] = "admin"
		case "isAdmin", "is_admin":
			out[f] = true
		case "ownerId":
			out[f] = injectedOwner(env, self)
		}
	}
	return out
}

// injectedOwner is the ownerId injected for self: the first userId of the
// first other non-anonymous profile (by name) that has one, as a JSON number
// when it parses as an integer; fallbackOwnerID when there is none.
func injectedOwner(env *Env, self string) any {
	for _, p := range sortedProfiles(env.Profiles) {
		if p.IsAnonymous() || p.Name == self {
			continue
		}
		ids := env.Pool.IDs(p.Name, "userId")
		if len(ids) == 0 {
			continue
		}
		if n, err := strconv.ParseInt(ids[0], 10, 64); err == nil {
			return n
		}
		return ids[0]
	}
	return fallbackOwnerID
}

// selves are the profiles that write their own objects: every
// non-anonymous, non-admin profile, by name. An admin may legitimately set
// privileged fields, and injecting role=admin as one proves nothing.
func selves(env *Env) []*identity.Profile {
	var out []*identity.Profile
	for _, p := range sortedProfiles(env.Profiles) {
		if !p.IsAnonymous() && !p.IsAdmin() {
			out = append(out, p)
		}
	}
	return out
}

func (c *massAssignCheck) Plan(ep spec.Endpoint, env *Env) []PlannedRequest {
	get, ok := sameGET(ep, env)
	if !ok {
		return nil
	}
	var out []PlannedRequest
	for _, p := range selves(env) {
		extra := injectedFields(ep, env, p.Name)
		if len(extra) == 0 {
			continue
		}
		steps := []struct {
			name, method string
			ep           spec.Endpoint
			extra        map[string]any
		}{{"before", http.MethodGet, get, nil}, {"inject", ep.Method, ep, extra}, {"after", http.MethodGet, get, nil}}
		for _, s := range steps {
			req, err := env.Builder.Build(s.ep, s.method, p.Name, s.extra)
			if err != nil {
				env.logger().Warn("plan: build request", "rule", c.rule.ID, "endpoint", ep.Key(), "err", err)
				break
			}
			if unownedDestructive(req) {
				break
			}
			out = append(out, PlannedRequest{RuleID: c.rule.ID, Endpoint: ep.Key(), Step: s.name, Profile: p.Name,
				Method: s.method, Path: req.Path, Destructive: isDestructive(s.method)})
		}
	}
	return out
}

func (c *massAssignCheck) Run(ctx context.Context, ep spec.Endpoint, env *Env) (Outcome, error) {
	var out Outcome
	get, ok := sameGET(ep, env)
	if !ok {
		return out, nil
	}
	for _, p := range selves(env) {
		f, obs, err := c.runProfile(ctx, ep, get, env, p)
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

// runProfile performs before-GET, injected write and after-GET as p.
func (c *massAssignCheck) runProfile(ctx context.Context, ep, get spec.Endpoint, env *Env, p *identity.Profile) (*finding.Finding, []Observation, error) {
	extra := injectedFields(ep, env, p.Name)
	if len(extra) == 0 {
		return nil, nil, nil
	}
	var obs []Observation
	var evidence []finding.Exchange
	// send builds and sends one step; a nil response means the step did not
	// produce a usable answer and the profile is done.
	send := func(step, method string, e spec.Endpoint, x map[string]any, need2xx bool) ([]byte, bool, error) {
		req, err := env.Builder.Build(e, method, p.Name, x)
		if err != nil {
			obs = append(obs, buildFailed(env, c.rule.ID, e, method, p.Name, step, err))
			return nil, false, nil
		}
		resp, o, err := probe(ctx, env, c.rule.ID, p, step, req)
		obs = append(obs, o)
		if err != nil || resp == nil || (need2xx && !isOK(resp.Status)) {
			return nil, false, err
		}
		evidence = append(evidence, resp.Exchange)
		return resp.Body, true, nil
	}

	before, ok, err := send("before", http.MethodGet, get, nil, true)
	if !ok {
		return nil, obs, err
	}
	if _, ok, err := send("inject", ep.Method, ep, extra, false); !ok {
		return nil, obs, err
	}
	after, ok, err := send("after", http.MethodGet, get, nil, true)
	if !ok {
		return nil, obs, err
	}

	persisted := persistedFields(before, after, extra)
	if len(persisted) == 0 {
		return nil, obs, nil
	}
	f := newFinding(c.rule, ep, ep.Method, p.Name, p.Name, finding.ConfHigh)
	f.Description += "\n\nPersisted fields: " + strings.Join(persisted, ", ") + "."
	f.Evidence = evidence
	return &f, obs, nil
}

// persistedFields returns, sorted, the injected fields whose value appears
// in after (at $.<field> or any nested <field> key) but not in before.
func persistedFields(before, after []byte, injected map[string]any) []string {
	fa, ok := compare.Flatten(after)
	if !ok {
		return nil
	}
	fb, _ := compare.Flatten(before)
	var out []string
	for field, v := range injected {
		want, ok := canonical(v)
		if !ok {
			continue
		}
		if hasValue(fa, field, want) && !hasValue(fb, field, want) {
			out = append(out, field)
		}
	}
	sort.Strings(out)
	return out
}

// canonical is v's canonical JSON leaf text as produced by compare.Flatten.
func canonical(v any) (string, bool) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	flat, ok := compare.Flatten(raw)
	if !ok {
		return "", false
	}
	c, ok := flat["$"]
	return c, ok
}

// hasValue reports whether a flattened leaf keyed field has canonical value want.
func hasValue(flat map[string]string, field, want string) bool {
	for path, v := range flat {
		if v == want && strings.HasSuffix(path, "."+field) { // $.<field> or nested
			return true
		}
	}
	return false
}
