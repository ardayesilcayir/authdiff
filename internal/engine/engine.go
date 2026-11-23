// Package engine runs authorization checks against every endpoint of an
// inventory as several identities and turns the responses into findings.
package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/planner"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// Env is the shared state checks run against.
type Env struct {
	Config   *config.Config
	Profiles []*identity.Profile
	Pool     *identity.Pool
	Builder  *planner.Builder
	Sender   Sender
	Log      *slog.Logger
	// Endpoints is the whole inventory, for checks that look at sibling
	// operations of the same path.
	Endpoints []spec.Endpoint

	matrix map[string][]string // config.Matrix as pattern -> allowed roles
}

// Observation is one probe of an endpoint by a profile, used for the matrix.
// Endpoint is the "METHOD /path" key of the request actually sent.
type Observation struct {
	Endpoint, Profile string
	Status            int
	Sent, OwnIDs      bool
	Err               string
	// Exchange is the recorded evidence of a sent 2xx probe (nil otherwise),
	// used by the post-run matrix evaluation.
	Exchange *finding.Exchange
}

// Outcome is what a check produced for one endpoint.
type Outcome struct {
	Findings     []finding.Finding
	Observations []Observation
}

// Progress is one scan progress event, passed to RunOptions.OnProgress.
// Sent, Blocked and Errors are cumulative over the whole scan (the
// transport's request, blocked and error counts) and never decrease.
type Progress struct {
	// Phase is 0 harvest, 1 read, 2 write, 3 swap, 4 delete, 5 finish;
	// PhaseName is the matching name.
	Phase     int
	PhaseName string
	// Planned is RunOptions.Planned (the dry-run plan size); harvest
	// requests are not planned, so Sent can exceed it.
	Planned               int
	Sent, Blocked, Errors int
	// Finding is set on the event for a finding a check just produced. It
	// is a read-only copy; the same ID may be reported more than once.
	Finding *finding.Finding
	// Done is set on the last event only, after the result is assembled.
	Done bool
}

// PlannedRequest is a request a check would send, reported by dry runs.
type PlannedRequest struct {
	RuleID, Endpoint, Step, Profile, Method, Path string
	Destructive                                   bool
}

// Check is one executable rule.
type Check interface {
	Rule() *rules.Rule
	Applies(ep spec.Endpoint, env *Env) bool
	Phase(ep spec.Endpoint) int
	Plan(ep spec.Endpoint, env *Env) []PlannedRequest
	Run(ctx context.Context, ep spec.Endpoint, env *Env) (Outcome, error)
}

// registry maps non-template rule kinds to their check constructors.
var registry = map[string]func(*rules.Rule) Check{}

// NewChecks builds a check for each rule. Template rules always work; other
// kinds need a constructor in the registry.
func NewChecks(rs []rules.Rule) ([]Check, error) {
	out := make([]Check, 0, len(rs))
	for i := range rs {
		r := &rs[i]
		kind := r.Kind
		if kind == "" || kind == rules.KindTemplate {
			out = append(out, &templateCheck{rule: r})
			continue
		}
		ctor, ok := registry[kind]
		if !ok {
			return nil, fmt.Errorf("rule %s: no check registered for kind %q", r.ID, kind)
		}
		out = append(out, ctor(r))
	}
	return out, nil
}

// isDestructive reports whether method changes server state.
func isDestructive(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodDelete, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

// deletePhase is the phase of DELETE endpoints; it runs sequentially.
const deletePhase = 4

// methodPhase is the phase an endpoint with this method runs in: reads and
// creates first, then updates, then deletes (3 is reserved for method swaps).
func methodPhase(method string) int {
	switch strings.ToUpper(method) {
	case http.MethodPut, http.MethodPatch:
		return 2
	case http.MethodDelete:
		return deletePhase
	}
	return 1
}

// matrixOf converts config.Matrix into the pattern -> roles form used by spec.
func matrixOf(c *config.Config) map[string][]string {
	if c == nil || len(c.Matrix) == 0 {
		return nil
	}
	m := make(map[string][]string, len(c.Matrix))
	for k, v := range c.Matrix {
		m[k] = v.Allow
	}
	return m
}

// Matrix returns the configured authorization matrix as pattern -> allowed roles.
func (e *Env) Matrix() map[string][]string {
	if e.matrix != nil {
		return e.matrix
	}
	return matrixOf(e.Config)
}

// matrixAllow returns the union of the allow lists of every matrix rule
// matching ep, and whether any rule matched.
func (e *Env) matrixAllow(ep spec.Endpoint) ([]string, bool) {
	return matrixAllowOf(e.Matrix(), ep)
}

// matrixAllowOf is matrixAllow for an explicit pattern -> roles matrix.
func matrixAllowOf(m map[string][]string, ep spec.Endpoint) ([]string, bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var allow []string
	found := false
	for _, k := range keys {
		if spec.MatchEndpoint(k, ep) {
			found = true
			allow = append(allow, m[k]...)
		}
	}
	return allow, found
}

func (e *Env) logger() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (e *Env) threshold() float64 {
	if e.Config != nil && e.Config.Compare.SimilarityThreshold > 0 {
		return e.Config.Compare.SimilarityThreshold
	}
	return 0.85
}

// newEnv builds the shared environment from the config.
func newEnv(c *config.Config, s Sender, log *slog.Logger, eps ...spec.Endpoint) *Env {
	profiles := identity.FromConfig(c)
	names := make([]string, len(profiles))
	for i, p := range profiles {
		names[i] = p.Name
	}
	pool := identity.NewPool(c)
	return &Env{
		Config:    c,
		Profiles:  profiles,
		Pool:      pool,
		Builder:   planner.NewBuilder(c.Target.BaseURL, c.Bodies, pool, names),
		Sender:    s,
		Log:       log,
		Endpoints: eps,
		matrix:    matrixOf(c),
	}
}
