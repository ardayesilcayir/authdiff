package engine

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// progressLog collects hook events; the hook may be called from several
// goroutines.
type progressLog struct {
	mu     sync.Mutex
	events []Progress
}

func (l *progressLog) hook(p Progress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, p)
}

func TestProgressEvents(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	cfg := testConfig(api.URL)
	// Destructive mode: in safe mode a blocked write makes some checks skip
	// their follow-up request, and the plan is then only an upper bound.
	cfg.Safety.AllowDestructive = true
	all, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	inv := &spec.Inventory{Endpoints: []spec.Endpoint{epGetOrder, epPatchOrder}}
	plan, err := DryRun(RunOptions{Config: cfg, Inventory: inv, Rules: all})
	if err != nil {
		t.Fatal(err)
	}
	var log progressLog
	res, err := Run(context.Background(), RunOptions{
		Config: cfg, Inventory: inv, Rules: all,
		Client:     newTestClient(t, api, true),
		Planned:    len(plan),
		OnProgress: log.hook,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ev := log.events
	if len(ev) == 0 {
		t.Fatal("no progress events")
	}

	order := map[string]int{"harvest": 0, "read": 1, "write": 2, "swap": 3, "delete": 4, "finish": 5}
	var dones, findings int
	prev := Progress{}
	for i, p := range ev {
		rank, ok := order[p.PhaseName]
		if !ok {
			t.Fatalf("event %d: unknown phase %q", i, p.PhaseName)
		}
		if rank != p.Phase {
			t.Errorf("event %d: phase %d named %q", i, p.Phase, p.PhaseName)
		}
		if p.Phase < prev.Phase {
			t.Errorf("event %d: phase went back from %s to %s", i, prev.PhaseName, p.PhaseName)
		}
		if p.Sent < prev.Sent || p.Blocked < prev.Blocked || p.Errors < prev.Errors {
			t.Errorf("event %d: counters decreased: %+v after %+v", i, p, prev)
		}
		if p.Planned != len(plan) {
			t.Errorf("event %d: planned = %d, want %d", i, p.Planned, len(plan))
		}
		if p.Done {
			dones++
		}
		if p.Finding != nil {
			findings++
		}
		prev = p
	}
	last := ev[len(ev)-1]
	if dones != 1 || !last.Done {
		t.Fatalf("done events = %d, last = %+v", dones, last)
	}
	if last.Sent != res.Stats.Requests || last.Blocked != res.Stats.Blocked || last.Errors != res.Stats.Errors {
		t.Errorf("last event %+v != stats %+v", last, res.Stats)
	}
	if last.Planned != last.Sent {
		t.Errorf("no harvest: planned %d != sent %d", last.Planned, last.Sent)
	}
	if findings == 0 || len(res.Findings) == 0 {
		t.Errorf("finding events = %d, findings = %d", findings, len(res.Findings))
	}
}

func TestProgressNilHookIsNoop(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetOrder}, templateRules(t, RuleBOLARead))
	if len(findingsOf(res, RuleBOLARead)) == 0 {
		t.Fatalf("nil hook changed the scan: %+v", res.Findings)
	}
}

func TestProgressSafeModeCountsBlocked(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	cfg := testConfig(api.URL)
	all, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	inv := &spec.Inventory{Endpoints: []spec.Endpoint{epGetOrder, epPatchOrder}}
	plan, err := DryRun(RunOptions{Config: cfg, Inventory: inv, Rules: all})
	if err != nil {
		t.Fatal(err)
	}
	var log progressLog
	res, err := Run(context.Background(), RunOptions{Config: cfg, Inventory: inv, Rules: all,
		Client: newTestClient(t, api, false), Planned: len(plan), OnProgress: log.hook})
	if err != nil {
		t.Fatal(err)
	}
	last := log.events[len(log.events)-1]
	if last.Blocked == 0 || last.Blocked != res.Stats.Blocked || last.Sent != res.Stats.Requests {
		t.Errorf("last = %+v, stats %+v", last, res.Stats)
	}
	if last.Sent > last.Planned {
		t.Errorf("sent %d > planned %d without harvest", last.Sent, last.Planned)
	}
}

func TestProgressHarvestPhase(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		if r.URL.Path == "/me/orders" {
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{"id": "555"}}})
			return
		}
		unprotectedOrders(w, r, user)
	})
	cfg := testConfig(api.URL)
	cfg.Harvest = []config.HarvestRule{{Endpoint: "GET /me/orders", Extract: map[string]string{"id": "$.items[*].id"}}}
	epMeOrders := spec.Endpoint{Method: "GET", Path: "/me/orders", Secured: true}
	var log progressLog
	_, err := Run(context.Background(), RunOptions{Config: cfg,
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epGetOrder, epMeOrders}},
		Rules:     templateRules(t, RuleBOLARead), Client: newTestClient(t, api, false), OnProgress: log.hook})
	if err != nil {
		t.Fatal(err)
	}
	first := log.events[0]
	if first.PhaseName != "harvest" || first.Sent != 0 {
		t.Errorf("first event = %+v, want harvest start", first)
	}
	var harvestSends int
	for _, p := range log.events {
		if p.PhaseName == "harvest" && p.Sent > 0 {
			harvestSends++
		}
	}
	if harvestSends == 0 {
		t.Error("no send events during harvest")
	}
}

func TestProgressSenderOnlyCountsErrors(t *testing.T) {
	var log progressLog
	_, err := Run(context.Background(), RunOptions{
		Config:     testConfig("http://x"),
		Inventory:  &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules:      templateRules(t, RuleNOAUTH),
		Sender:     errSender{},
		OnProgress: log.hook,
	})
	if err != nil {
		t.Fatal(err)
	}
	last := log.events[len(log.events)-1]
	if !last.Done || last.Sent == 0 || last.Errors != last.Sent || last.Blocked != 0 {
		t.Errorf("last = %+v, want every send counted as an error", last)
	}
}

func TestProgressBlockedWithoutClient(t *testing.T) {
	var log progressLog
	_, err := Run(context.Background(), RunOptions{
		Config:     testConfig("http://x"),
		Inventory:  &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules:      templateRules(t, RuleNOAUTH),
		Sender:     errSender{err: transport.ErrOutOfScope},
		OnProgress: log.hook,
	})
	if err != nil {
		t.Fatal(err)
	}
	last := log.events[len(log.events)-1]
	if last.Sent == 0 || last.Blocked != last.Sent || last.Errors != 0 {
		t.Errorf("last = %+v, want every send counted as blocked", last)
	}
}

func TestProgressDoneOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var log progressLog
	_, err := Run(ctx, RunOptions{
		Config:     testConfig("http://x"),
		Inventory:  &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules:      templateRules(t, RuleNOAUTH),
		Sender:     errSender{err: context.Canceled},
		OnProgress: log.hook,
	})
	if err == nil {
		t.Fatal("want cancellation error")
	}
	if n := len(log.events); n == 0 || !log.events[n-1].Done || log.events[n-1].PhaseName != "finish" {
		t.Errorf("events = %+v, want a final finish/Done event", log.events)
	}
}

func TestPhaseNameUnknown(t *testing.T) {
	if got := phaseName(9); got != "phase 9" {
		t.Errorf("phaseName(9) = %q", got)
	}
}
