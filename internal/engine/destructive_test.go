package engine

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// NOAUTH's reference step never sends the endpoint's destructive method: a
// DELETE as any_user would delete the object before the anonymous probe.
func TestNOAUTHRefNeverDestructive(t *testing.T) {
	cfg := testConfig("http://api.test")
	cfg.Safety.AllowDestructive = true
	plan, err := DryRun(RunOptions{
		Config:    cfg,
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epGetOrder, epPatchOrder, epDeleteOrder}},
		Rules:     templateRules(t, RuleNOAUTH),
	})
	if err != nil {
		t.Fatal(err)
	}
	sawAnon := false
	for _, p := range plan {
		if p.Step == "ref" && p.Destructive {
			t.Errorf("destructive ref planned: %+v", p)
		}
		if p.Step == "anon" && p.Method == "DELETE" {
			sawAnon = true
		}
	}
	if !sawAnon {
		t.Errorf("anonymous DELETE probe missing: %+v", plan)
	}

	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	cfg = testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	runScan(t, api, cfg, []spec.Endpoint{epDeleteOrder}, templateRules(t, RuleNOAUTH))
	for _, h := range api.Hits() {
		if h.Method == "DELETE" && h.Who != "" {
			t.Errorf("authenticated DELETE sent by NOAUTH: %+v", h)
		}
	}
}

// A destructive request whose path IDs no configured profile owns is never
// sent (nor planned): it would hit an arbitrary object.
func TestDestructiveUnownedIDsSkipped(t *testing.T) {
	ep := spec.Endpoint{Method: "DELETE", Path: "/things/{thingId}", Secured: true, Params: []spec.Param{pathParam("thingId")}}
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	all := builtinRules(t, RuleBOLAWrite, RuleBFLA, RuleNOAUTH, RuleMethodSwap)
	runScan(t, api, cfg, []spec.Endpoint{ep}, all)
	for _, h := range api.Hits() {
		if isDestructive(h.Method) {
			t.Errorf("destructive request with unowned IDs sent: %+v", h)
		}
	}
	plan, err := DryRun(RunOptions{Config: cfg, Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{ep}}, Rules: all})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plan {
		if p.Destructive {
			t.Errorf("destructive request with unowned IDs planned: %+v", p)
		}
	}
}

// Method swap never sends a destructive method to a collection path and
// never probes as an admin profile.
func TestMethodSwapNoAdminNoCollectionDestructive(t *testing.T) {
	coll := spec.Endpoint{Method: "GET", Path: "/orders", Secured: true}
	api := newAPI(t, swapAPI(http.StatusOK))
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	eps := []spec.Endpoint{coll, epGetOrder}
	runScan(t, api, cfg, eps, builtinRules(t, RuleMethodSwap))
	for _, h := range api.Hits() {
		if h.Who == "admin" {
			t.Errorf("method swap probed as admin: %+v", h)
		}
		if h.Path == "/orders" && isDestructive(h.Method) {
			t.Errorf("destructive swap on collection path: %+v", h)
		}
	}
	env := newEnv(cfg, nil, nil, eps...)
	c, _ := NewChecks(builtinRules(t, RuleMethodSwap))
	for _, p := range c[0].Plan(coll, env) {
		if p.Destructive || p.Profile == "admin" {
			t.Errorf("bad planned swap: %+v", p)
		}
	}
}

// The DELETE phase runs one endpoint at a time, in endpoint order.
func TestDeletePhaseSequential(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	var mu sync.Mutex
	var order []string
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.Method == http.MethodDelete {
			n := inFlight.Add(1)
			for {
				m := maxInFlight.Load()
				if n <= m || maxInFlight.CompareAndSwap(m, n) {
					break
				}
			}
			mu.Lock()
			order = append(order, r.URL.Path)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
		}
		w.WriteHeader(http.StatusForbidden)
	})
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	cfg.Safety.Concurrency = 4
	var eps []spec.Endpoint
	for _, p := range []string{"/a/{id}", "/b/{id}", "/c/{id}", "/d/{id}"} {
		eps = append(eps, spec.Endpoint{Method: "DELETE", Path: p, Secured: true, Params: []spec.Param{pathParam("id")}})
	}
	runScan(t, api, cfg, eps, templateRules(t, RuleBOLAWrite))
	if m := maxInFlight.Load(); m > 1 {
		t.Errorf("DELETE phase ran %d requests concurrently", m)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := 1; i < len(order); i++ {
		if order[i] < order[i-1] {
			t.Errorf("DELETE order not endpoint order: %v", order)
			break
		}
	}
}

// Mass assignment never injects privileged fields as an admin profile.
func TestMassAssignSkipsAdmin(t *testing.T) {
	cfg := testConfig("http://api.test")
	env := newEnv(cfg, nil, nil)
	for _, p := range selves(env) {
		if p.IsAdmin() {
			t.Errorf("admin %s is a mass-assignment self", p.Name)
		}
	}
}
