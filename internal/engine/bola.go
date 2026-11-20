package engine

import (
	"context"

	"github.com/ardayesilcayir/authdiff/internal/compare"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/planner"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// Built-in BOLA rule IDs.
const (
	RuleBOLARead  = "AD-BOLA-001"
	RuleBOLAWrite = "AD-BOLA-002"
)

// sendRepeats implements a step's "repeat": the request is re-sent
// Repeat-1 more times and every path whose value changed against the first
// response is added to dyn, so the owner's timestamps and request IDs are
// masked when the owner response is compared with others (PRD 7.1 step 2).
// Failed repeats are ignored unless the context is done.
func sendRepeats(ctx context.Context, env *Env, p *identity.Profile, s rules.Step, req planner.Request,
	first *transport.Response, dyn map[string]bool) error {
	for i := 1; i < s.Repeat; i++ {
		again, err := env.Sender.Send(ctx, p, s.Name, req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		for k := range compare.DynamicPaths(first.Body, again.Body) {
			dyn[k] = true
		}
	}
	return nil
}
