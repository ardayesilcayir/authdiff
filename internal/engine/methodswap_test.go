package engine

import (
	"net/http"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// swapAPI serves GET /orders/{id} to owners; undeclared methods get
// undeclared (or 405 when undeclared is 0).
func swapAPI(undeclared int) func(w http.ResponseWriter, r *http.Request, user string) {
	return func(w http.ResponseWriter, r *http.Request, user string) {
		switch r.Method {
		case http.MethodGet:
			id := orderID(r.URL.Path)
			if orders[id] != user {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
				return
			}
			writeJSON(w, http.StatusOK, orderBody(id))
		case http.MethodDelete:
			if undeclared != 0 {
				w.WriteHeader(undeclared)
				return
			}
			fallthrough
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func TestMethodSwapFinds(t *testing.T) {
	api := newAPI(t, swapAPI(http.StatusOK))
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res := runScan(t, api, cfg, []spec.Endpoint{epGetOrder}, builtinRules(t, RuleMethodSwap))

	fs := findingsOf(res, RuleMethodSwap)
	if len(fs) != 2 {
		t.Fatalf("want DELETE findings for bob and anon, got %+v", res.Findings)
	}
	f := findPair(fs, "alice", "bob")
	if f == nil || f.Method != "DELETE" || f.Path != "/orders/{id}" || f.Confidence != finding.ConfMedium || f.Line != 12 {
		t.Fatalf("bob finding = %+v", fs)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].URL != api.URL+"/orders/101" || f.Evidence[0].RequestBody != "{}" {
		t.Errorf("evidence = %+v", f.Evidence)
	}
	if findPair(fs, "alice", "anon") == nil {
		t.Errorf("anon finding missing: %+v", fs)
	}
	// POST, PUT, PATCH, DELETE once each for bob and anon; GET never swapped.
	counts := map[string]int{}
	for _, h := range api.Hits() {
		counts[h.Method]++
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if counts[m] != 2 {
			t.Errorf("%s sent %d times, want 2 (%v)", m, counts[m], counts)
		}
	}
	if counts["GET"] != 0 {
		t.Errorf("declared GET must not be probed: %v", counts)
	}
}

func TestMethodSwapSilent405(t *testing.T) {
	api := newAPI(t, swapAPI(0))
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res := runScan(t, api, cfg, []spec.Endpoint{epGetOrder}, builtinRules(t, RuleMethodSwap))
	if len(res.Findings) != 0 {
		t.Fatalf("405 must be silent, got %+v", res.Findings)
	}
}

func TestMethodSwapSafeModeSkips(t *testing.T) {
	api := newAPI(t, swapAPI(http.StatusOK))
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetOrder}, builtinRules(t, RuleMethodSwap))
	for _, h := range api.Hits() {
		if isDestructive(h.Method) {
			t.Fatalf("safe mode sent %s", h.Method)
		}
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

// Declared methods are not swapped and a path is probed once, from its
// first non-destructive method.
func TestMethodSwapOncePerPath(t *testing.T) {
	api := newAPI(t, swapAPI(http.StatusOK))
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	eps := []spec.Endpoint{epGetOrder, epPatchOrder, epDeleteOrder}
	res := runScan(t, api, cfg, eps, builtinRules(t, RuleMethodSwap))
	counts := map[string]int{}
	for _, h := range api.Hits() {
		counts[h.Method]++
	}
	if counts["POST"] != 2 || counts["PUT"] != 2 || counts["PATCH"] != 0 || counts["DELETE"] != 0 {
		t.Errorf("hits = %v", counts)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}

	env := newEnv(cfg, nil, nil)
	env.Endpoints = eps
	c, _ := NewChecks(builtinRules(t, RuleMethodSwap))
	if !c[0].Applies(epGetOrder, env) || c[0].Applies(epPatchOrder, env) || c[0].Applies(epDeleteOrder, env) {
		t.Error("must attach to GET only")
	}
	if c[0].Phase(epGetOrder) != 3 {
		t.Error("phase must be 3")
	}
	plan := c[0].Plan(epGetOrder, env)
	if len(plan) != 4 || plan[0].Method != "POST" || plan[1].Profile != "anon" || !plan[2].Destructive {
		t.Errorf("plan = %+v", plan)
	}
}

// Without an owner of the path IDs the attacker is any_user.
func TestMethodSwapAnyUserFallback(t *testing.T) {
	ep := spec.Endpoint{Method: "GET", Path: "/things/{thingId}", Secured: true, Params: []spec.Param{pathParam("thingId")}}
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{ep}, builtinRules(t, RuleMethodSwap))
	fs := findingsOf(res, RuleMethodSwap)
	if len(fs) != 2 || findPair(fs, "", "admin") == nil || findPair(fs, "", "anon") == nil {
		t.Fatalf("want POST findings for any_user (admin) and anon, got %+v", fs)
	}
}
