package engine

import (
	"errors"
	"strconv"
	"sync"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// Progress phases outside the check phases (1 read, 2 write, 3 swap,
// 4 delete).
const (
	harvestPhase = 0
	finishPhase  = 5
)

var phaseNames = map[int]string{
	harvestPhase: "harvest",
	1:            "read",
	2:            "write",
	3:            "swap",
	deletePhase:  "delete",
	finishPhase:  "finish",
}

func phaseName(ph int) string {
	if n, ok := phaseNames[ph]; ok {
		return n
	}
	return "phase " + strconv.Itoa(ph)
}

// progress delivers Progress events to a hook. Every event is built and
// delivered under mu, so the hook is never called concurrently and the
// counters it sees never decrease, even though events are raised from the
// engine's worker goroutines. A nil *progress (no hook) does nothing.
type progress struct {
	hook    func(Progress)
	client  *transport.Client // counter source when set
	planned int

	mu                    sync.Mutex
	phase                 int
	sent, blocked, errors int // counted here only when client is nil
}

func newProgress(o RunOptions) *progress {
	if o.OnProgress == nil {
		return nil
	}
	return &progress{hook: o.OnProgress, client: o.Client, planned: o.Planned}
}

// emitLocked delivers one event; mu must be held.
func (p *progress) emitLocked(f *finding.Finding, done bool) {
	ev := Progress{Phase: p.phase, PhaseName: phaseName(p.phase), Planned: p.planned,
		Sent: p.sent, Blocked: p.blocked, Errors: p.errors, Finding: f, Done: done}
	if p.client != nil {
		ev.Sent, ev.Blocked, ev.Errors = p.client.Stats()
	}
	p.hook(ev)
}

// startPhase records ph as the current phase and reports it.
func (p *progress) startPhase(ph int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase = ph
	p.emitLocked(nil, false)
}

// findings reports each finding as its own event.
func (p *progress) findings(fs []finding.Finding) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range fs {
		f := fs[i]
		p.emitLocked(&f, false)
	}
}

// afterSend reports one finished Send; err classifies it when there is no client.
func (p *progress) afterSend(err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil {
		p.sent++
		switch {
		case err == nil:
		case errors.Is(err, transport.ErrOutOfScope), errors.Is(err, transport.ErrDestructiveBlocked):
			p.blocked++
		default:
			p.errors++
		}
	}
	p.emitLocked(nil, false)
}

// done reports the final event.
func (p *progress) done() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase = finishPhase
	p.emitLocked(nil, true)
}
