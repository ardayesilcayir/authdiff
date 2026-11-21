package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// RunOptions configures a scan.
type RunOptions struct {
	Config    *config.Config
	Inventory *spec.Inventory
	Rules     []rules.Rule
	Client    *transport.Client
	Sender    Sender // nil means NewSender(Client)
	Log       *slog.Logger
	Version   string
}

func (o RunOptions) validate() error {
	if o.Config == nil {
		return errors.New("engine: config is required")
	}
	if o.Inventory == nil {
		return errors.New("engine: inventory is required")
	}
	return nil
}

// phasesOf returns the distinct phases of every applicable (endpoint, check)
// pair, ascending.
func phasesOf(eps []spec.Endpoint, checks []Check, env *Env) []int {
	seen := map[int]bool{}
	var out []int
	for _, ep := range eps {
		for _, c := range checks {
			if ph := c.Phase(ep); !seen[ph] && c.Applies(ep, env) {
				seen[ph] = true
				out = append(out, ph)
			}
		}
	}
	sort.Ints(out)
	return out
}

// Run executes the scan: harvest, then every phase in ascending order with
// up to Safety.Concurrency endpoints in flight (the DELETE phase runs
// sequentially); the checks of one endpoint run
// sequentially on the same worker. Output is deterministic.
func Run(ctx context.Context, o RunOptions) (*finding.Result, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	sender := o.Sender
	if sender == nil {
		if o.Client == nil {
			return nil, errors.New("engine: a transport client or sender is required")
		}
		sender = NewSender(o.Client)
	}
	checks, err := NewChecks(o.Rules)
	if err != nil {
		return nil, err
	}
	env := newEnv(o.Config, sender, o.Log, o.Inventory.Endpoints...)
	started := time.Now()

	// finish assembles the result from whatever has been collected. It is
	// also used on cancellation so callers can still write a partial report.
	var findings []finding.Finding
	var observations []Observation
	eps := o.Inventory.Endpoints
	finish := func(runErr error) (*finding.Result, error) {
		findings = append(findings, matrixFindings(checks, o.Config, observations, findings, eps)...)
		merged := mergeFindings(findings)
		finding.Sort(merged)
		keys := make(map[string]bool, len(eps))
		for _, ep := range eps {
			keys[ep.Key()] = true
		}
		res := &finding.Result{
			Tool:       finding.Tool{Name: "authdiff", Version: o.Version},
			Target:     o.Config.Target.BaseURL,
			SpecPath:   o.Inventory.SpecPath,
			StartedAt:  started,
			FinishedAt: time.Now(),
			Profiles:   make([]string, 0, len(env.Profiles)),
			Rules:      make([]finding.RuleMeta, 0, len(o.Rules)),
			Findings:   merged,
			Matrix:     buildMatrix(observations, merged, keys),
			Stats:      finding.Stats{Endpoints: len(eps)},
		}
		for _, p := range env.Profiles {
			res.Profiles = append(res.Profiles, p.Name)
		}
		for i := range o.Rules {
			res.Rules = append(res.Rules, o.Rules[i].Meta())
		}
		if o.Client != nil {
			res.Stats.Requests, res.Stats.Blocked, res.Stats.Errors = o.Client.Stats()
		}
		if runErr == nil {
			warnNo2xx(env, observations)
		}
		return res, runErr
	}

	if err := harvest(ctx, env, o.Inventory); err != nil {
		return finish(err)
	}

	limit := o.Config.Safety.Concurrency
	if limit < 1 {
		limit = 4
	}
	log := env.logger()
	for _, phase := range phasesOf(eps, checks, env) {
		outs := make([]Outcome, len(eps))
		var g errgroup.Group
		if phase == deletePhase {
			// Deletes run one endpoint at a time in endpoint order, so whether
			// an object (or the attacker's own account) still exists when a
			// probe runs never depends on scheduling.
			g.SetLimit(1)
		} else {
			g.SetLimit(limit)
		}
		for i, ep := range eps {
			g.Go(func() error {
				for _, c := range checks {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					if c.Phase(ep) != phase || !c.Applies(ep, env) {
						continue
					}
					out, err := c.Run(ctx, ep, env)
					outs[i].Findings = append(outs[i].Findings, out.Findings...)
					outs[i].Observations = append(outs[i].Observations, out.Observations...)
					if err != nil {
						// Only the caller's cancellation stops the scan; a failing
						// check loses its own endpoint result, nothing else.
						if ctx.Err() != nil {
							return ctx.Err()
						}
						log.Warn("check failed", "rule", c.Rule().ID, "endpoint", ep.Key(), "err", err)
					}
				}
				return nil
			})
		}
		err := g.Wait()
		// Collected by endpoint index, so the order never depends on scheduling.
		for _, out := range outs {
			findings = append(findings, out.Findings...)
			observations = append(observations, out.Observations...)
		}
		if err != nil {
			return finish(err)
		}
	}
	return finish(ctx.Err())
}

// warnNo2xx logs a warning for every authenticated profile that never got a
// 2xx response: its credentials are probably invalid or expired, and every
// check that needed it tested nothing.
func warnNo2xx(env *Env, obs []Observation) {
	ok := map[string]bool{}
	for _, o := range obs {
		if o.Sent && isOK(o.Status) {
			ok[o.Profile] = true
		}
	}
	for _, p := range env.Profiles {
		if !p.IsAnonymous() && !ok[p.Name] {
			env.logger().Warn("authenticated profile never received a 2xx response; check its credentials and owned IDs",
				"profile", p.Name)
		}
	}
}

// matrixFindings runs EvaluateMatrix for the first matrix-kind check, if
// any, and fills each finding's source line from the inventory.
func matrixFindings(checks []Check, cfg *config.Config, obs []Observation, existing []finding.Finding, eps []spec.Endpoint) []finding.Finding {
	for _, c := range checks {
		if c.Rule().Kind != rules.KindMatrix {
			continue
		}
		fs := EvaluateMatrix(cfg, obs, existing, c.Rule())
		for i := range fs {
			for _, ep := range eps {
				if ep.Method == fs[i].Method && ep.Path == fs[i].Path {
					fs[i].Line = ep.Line
					break
				}
			}
		}
		return fs
	}
	return nil
}

// DryRun lists the requests a scan would send, in execution order, without
// touching the network. Harvest rules are not run, so only configured IDs are used.
func DryRun(o RunOptions) ([]PlannedRequest, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	checks, err := NewChecks(o.Rules)
	if err != nil {
		return nil, err
	}
	env := newEnv(o.Config, nil, o.Log, o.Inventory.Endpoints...)
	eps := o.Inventory.Endpoints
	out := []PlannedRequest{}
	for _, phase := range phasesOf(eps, checks, env) {
		for _, ep := range eps {
			for _, c := range checks {
				if c.Phase(ep) == phase && c.Applies(ep, env) {
					out = append(out, c.Plan(ep, env)...)
				}
			}
		}
	}
	return out, nil
}

// harvest runs the config's harvest rules as every non-anonymous profile and
// adds the extracted IDs to that profile's pool. Destructive methods are
// never used; failures are logged and skipped.
func harvest(ctx context.Context, env *Env, inv *spec.Inventory) error {
	log := env.logger()
	for _, h := range env.Config.Harvest {
		method, path := "GET", strings.TrimSpace(h.Endpoint)
		if i := strings.IndexAny(path, " \t"); i > 0 {
			method, path = strings.ToUpper(path[:i]), strings.TrimSpace(path[i+1:])
		}
		if isDestructive(method) {
			log.Warn("harvest: skipping destructive endpoint", "endpoint", h.Endpoint)
			continue
		}
		ep := spec.Endpoint{Method: method, Path: path}
		for _, e := range inv.Endpoints {
			if e.Method == method && e.Path == path {
				ep = e
				break
			}
		}
		for _, p := range sortedProfiles(env.Profiles) {
			if p.IsAnonymous() {
				continue
			}
			req, err := env.Builder.Build(ep, method, p.Name, nil)
			if err != nil {
				log.Warn("harvest: build request", "endpoint", h.Endpoint, "err", err)
				continue
			}
			resp, err := env.Sender.Send(ctx, p, "harvest", req)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Warn("harvest: request failed", "endpoint", h.Endpoint, "profile", p.Name, "err", err)
				continue
			}
			if resp.Status < 200 || resp.Status >= 300 {
				continue
			}
			extracted := identity.Extract(resp.Body, h.Extract)
			params := make([]string, 0, len(extracted))
			for k := range extracted {
				params = append(params, k)
			}
			sort.Strings(params)
			for _, k := range params {
				env.Pool.Add(p.Name, k, extracted[k]...)
			}
		}
	}
	return nil
}

// buildMatrix turns observations into one cell per inventory endpoint and
// profile, using the first sent observation: 2xx allowed; 429 and 5xx
// error; any other status (401, 403, 404, 405, ...) denied. A cell never sent is error when
// a probe failed, otherwise skipped. A profile that is the attacker of a
// finding on the endpoint is unexpected.
func buildMatrix(obs []Observation, fs []finding.Finding, endpoints map[string]bool) []finding.MatrixCell {
	type key struct{ ep, profile string }
	cells := map[key]*finding.MatrixCell{}
	sent := map[key]bool{}
	var order []key
	for _, o := range obs {
		if !endpoints[o.Endpoint] || o.Profile == "" {
			continue
		}
		k := key{o.Endpoint, o.Profile}
		c := cells[k]
		if c == nil {
			c = &finding.MatrixCell{Endpoint: o.Endpoint, Profile: o.Profile, Outcome: finding.Skipped}
			cells[k] = c
			order = append(order, k)
		}
		if sent[k] {
			continue
		}
		switch {
		case o.Sent:
			sent[k] = true
			c.Status = o.Status
			c.Outcome = statusOutcome(o.Status)
		case o.Err != "":
			c.Outcome = finding.Errored
		}
	}
	for _, f := range fs {
		if c := cells[key{f.Method + " " + f.Path, f.Attacker}]; c != nil && f.Attacker != "" {
			c.Outcome = finding.Unexpected
		}
	}
	out := make([]finding.MatrixCell, 0, len(order))
	for _, k := range order {
		out = append(out, *cells[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		return out[i].Profile < out[j].Profile
	})
	return out
}

func statusOutcome(status int) finding.Outcome {
	switch {
	case status >= 200 && status < 300:
		return finding.Allowed
	case status >= 500, status == http.StatusTooManyRequests:
		return finding.Errored
	}
	return finding.Denied
}

var confRank = map[finding.Confidence]int{finding.ConfLow: 1, finding.ConfMedium: 2, finding.ConfHigh: 3}

// mergeFindings collapses findings with the same ID into the first one,
// keeping the highest confidence seen.
func mergeFindings(fs []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(fs))
	idx := map[string]int{}
	for _, f := range fs {
		if i, ok := idx[f.ID]; ok {
			if confRank[f.Confidence] > confRank[out[i].Confidence] {
				out[i].Confidence = f.Confidence
			}
			continue
		}
		idx[f.ID] = len(out)
		out = append(out, f)
	}
	return out
}
