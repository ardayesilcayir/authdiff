package engine

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/planner"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// unprotectedOrders serves any order to any authenticated caller.
func unprotectedOrders(w http.ResponseWriter, r *http.Request, user string) {
	id := orderID(r.URL.Path)
	if user == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
		return
	}
	if _, ok := orders[id]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, orderBody(id))
}

func TestBOLAFinds(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetOrder}, templateRules(t, RuleBOLARead))

	fs := findingsOf(res, RuleBOLARead)
	f := findPair(fs, "alice", "bob")
	if f == nil {
		t.Fatalf("want AD-BOLA-001 alice->bob, got %+v", fs)
	}
	if f.Confidence != finding.ConfHigh {
		t.Errorf("confidence = %s, want high", f.Confidence)
	}
	if f.Similarity != 1.0 {
		t.Errorf("similarity = %v, want 1.0 (requestId must be masked as dynamic)", f.Similarity)
	}
	if f.ID != finding.NewID(RuleBOLARead, "GET", "/orders/{id}", "alice", "bob") {
		t.Errorf("unexpected ID %s", f.ID)
	}
	if f.Method != "GET" || f.Path != "/orders/{id}" || f.Line != 12 || f.Title == "" || f.Severity != finding.High {
		t.Errorf("finding fields wrong: %+v", f)
	}
	if f.OWASP != "API1:2023" || f.CWE != "CWE-639" || f.Remediation == "" || f.Description == "" || f.CVSS == 0 {
		t.Errorf("finding meta wrong: %+v", f)
	}
	// owner, attacker and anon were sent; owner's repeat is not kept twice.
	if len(f.Evidence) != 3 {
		t.Fatalf("evidence = %d exchanges, want 3", len(f.Evidence))
	}
	steps := []string{f.Evidence[0].Step, f.Evidence[1].Step, f.Evidence[2].Step}
	if strings.Join(steps, ",") != "owner,attacker,anon" {
		t.Errorf("evidence steps = %v", steps)
	}
	if f.Evidence[1].Profile != "bob" || !strings.HasSuffix(f.Evidence[1].URL, "/orders/101") {
		t.Errorf("attacker evidence = %+v", f.Evidence[1])
	}
	if strings.Contains(f.Evidence[1].RequestHeaders["Authorization"], "tok-bob") {
		t.Errorf("token not masked in evidence: %v", f.Evidence[1].RequestHeaders)
	}
	// the matrix marks bob as unexpected on the endpoint, anon as denied.
	cells := map[string]finding.Outcome{}
	for _, c := range res.Matrix {
		cells[c.Endpoint+"|"+c.Profile] = c.Outcome
	}
	if cells["GET /orders/{id}|bob"] != finding.Unexpected {
		t.Errorf("bob cell = %s, want unexpected (matrix %+v)", cells["GET /orders/{id}|bob"], res.Matrix)
	}
	if cells["GET /orders/{id}|anon"] != finding.Denied {
		t.Errorf("anon cell = %s, want denied", cells["GET /orders/{id}|anon"])
	}
	if res.Stats.Requests == 0 || res.Stats.Endpoints != 1 {
		t.Errorf("stats = %+v", res.Stats)
	}
	if res.Tool.Name != "authdiff" || res.Tool.Version != "test" || res.Target != api.URL || res.SpecPath != "openapi.yaml" {
		t.Errorf("result header = %+v", res)
	}
	if strings.Join(res.Profiles, ",") != "admin,alice,anon,bob" {
		t.Errorf("profiles = %v", res.Profiles)
	}
	if len(res.Rules) != 1 || res.Rules[0].ID != RuleBOLARead {
		t.Errorf("rules = %+v", res.Rules)
	}
}

func TestBOLASilentOnProtected(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		id := orderID(r.URL.Path)
		if orders[id] != user {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, orderBody(id))
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetOrder}, templateRules(t, RuleBOLARead))
	if fs := findingsOf(res, RuleBOLARead); len(fs) != 0 {
		t.Fatalf("want no BOLA findings, got %+v", fs)
	}
}

func TestBOLASilentOnPublic(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		writeJSON(w, http.StatusOK, orderBody(orderID(r.URL.Path)))
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetOrder}, templateRules(t, RuleBOLARead))
	if fs := findingsOf(res, RuleBOLARead); len(fs) != 0 {
		t.Fatalf("public resource must not be BOLA, got %+v", fs)
	}
}

func TestBOLASilentEmptyBody(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, user string) {
		if user == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetOrder}, templateRules(t, RuleBOLARead))
	if fs := findingsOf(res, RuleBOLARead); len(fs) != 0 {
		t.Fatalf("empty owner body must not be BOLA, got %+v", fs)
	}
}

func writableOrders(w http.ResponseWriter, r *http.Request, user string) {
	if r.Method == http.MethodPatch && user != "" {
		writeJSON(w, http.StatusOK, orderBody(orderID(r.URL.Path)))
		return
	}
	unprotectedOrders(w, r, user)
}

func TestBOLAWriteFinds(t *testing.T) {
	api := newAPI(t, writableOrders)
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res := runScan(t, api, cfg, []spec.Endpoint{epPatchOrder}, templateRules(t, RuleBOLAWrite))
	f := findPair(findingsOf(res, RuleBOLAWrite), "alice", "bob")
	if f == nil {
		t.Fatalf("want AD-BOLA-002 alice->bob, got %+v", res.Findings)
	}
	if f.Method != "PATCH" || f.Confidence != finding.ConfHigh {
		t.Errorf("finding = %+v", f)
	}
	var sawBobPatch bool
	for _, h := range api.Hits() {
		if h.Method == "PATCH" && h.Who == "bob" && h.Path == "/orders/101" {
			sawBobPatch = true
		}
	}
	if !sawBobPatch {
		t.Errorf("bob never patched alice's order: %+v", api.Hits())
	}
}

func TestBOLAWriteSafeMode(t *testing.T) {
	api := newAPI(t, writableOrders)
	cfg := testConfig(api.URL) // allowDestructive false
	res := runScan(t, api, cfg, []spec.Endpoint{epPatchOrder}, templateRules(t, RuleBOLAWrite))
	if len(res.Findings) != 0 {
		t.Fatalf("want no findings in safe mode, got %+v", res.Findings)
	}
	for _, h := range api.Hits() {
		if h.Method == "PATCH" {
			t.Fatalf("server received PATCH in safe mode: %+v", h)
		}
	}
	if res.Stats.Blocked == 0 {
		t.Errorf("want blocked requests counted, stats %+v", res.Stats)
	}
	for _, c := range res.Matrix {
		if c.Endpoint == "PATCH /orders/{id}" && c.Outcome != finding.Skipped {
			t.Errorf("blocked cell = %+v, want skipped", c)
		}
	}
}

var (
	epAdminUsers      = spec.Endpoint{Method: "GET", Path: "/admin/users", Secured: true}
	epAdminDeleteUser = spec.Endpoint{Method: "DELETE", Path: "/admin/users/{userId}", Secured: true, Params: []spec.Param{pathParam("userId")}}
)

func adminUsers(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, []any{map[string]any{"id": "u-alice"}, map[string]any{"id": "u-bob"}})
}

func TestBFLAFinds(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		if user == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		adminUsers(w, r, user)
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epAdminUsers}, templateRules(t, RuleBFLA))
	fs := findingsOf(res, RuleBFLA)
	if len(fs) != 2 {
		t.Fatalf("want 2 BFLA findings (alice, bob), got %+v", fs)
	}
	f := findPair(fs, "admin", "alice")
	if f == nil || f.Confidence != finding.ConfHigh {
		t.Fatalf("want admin->alice high, got %+v", fs)
	}
}

func TestBFLASilent(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		if user != "admin" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		adminUsers(w, r, user)
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epAdminUsers}, templateRules(t, RuleBFLA))
	if len(res.Findings) != 0 {
		t.Fatalf("want no findings, got %+v", res.Findings)
	}
}

func TestBFLADeleteUsesOwnID(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, user string) {
		if user == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	alice := cfg.Profiles["alice"]
	alice.Owns["userId"] = []string{"2"}
	bob := cfg.Profiles["bob"]
	bob.Owns["userId"] = []string{"3"}
	res := runScan(t, api, cfg, []spec.Endpoint{epAdminDeleteUser}, templateRules(t, RuleBFLA))

	var aliceDel bool
	for _, h := range api.Hits() {
		if h.Who == "admin" {
			t.Errorf("admin step must not be sent for a destructive method: %+v", h)
		}
		if h.Who == "alice" && h.Method == "DELETE" {
			if h.Path != "/admin/users/2" {
				t.Errorf("alice used %s, want her own id /admin/users/2", h.Path)
			}
			aliceDel = true
		}
	}
	if !aliceDel {
		t.Fatalf("alice never sent DELETE: %+v", api.Hits())
	}
	if findPair(findingsOf(res, RuleBFLA), "admin", "alice") == nil {
		t.Errorf("want BFLA finding for alice, got %+v", res.Findings)
	}
}

var (
	epProfile  = spec.Endpoint{Method: "GET", Path: "/users/me/profile", Secured: false}
	epProducts = spec.Endpoint{Method: "GET", Path: "/products", Secured: false}
)

func TestNOAUTHFinds(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"name": "Alice", "email": "alice@example.com"})
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epProfile}, templateRules(t, RuleNOAUTH))
	fs := findingsOf(res, RuleNOAUTH)
	if len(fs) != 1 {
		t.Fatalf("want 1 NOAUTH finding, got %+v", res.Findings)
	}
	if fs[0].Attacker != "anon" || fs[0].Confidence != finding.ConfHigh {
		t.Errorf("finding = %+v", fs[0])
	}
}

func TestNOAUTHSilentPublic(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, []any{map[string]any{"sku": "p-1", "name": "Pen"}})
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epProducts}, templateRules(t, RuleNOAUTH))
	if len(res.Findings) != 0 {
		t.Fatalf("public product list must be silent, got %+v", res.Findings)
	}
}

func TestNOAUTHMatrixForbids(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, []any{map[string]any{"sku": "p-1"}})
	})
	cfg := testConfig(api.URL)
	cfg.Matrix = map[string]config.MatrixRule{"GET /products": {Allow: []string{"user", "admin"}}}
	res := runScan(t, api, cfg, []spec.Endpoint{epProducts}, templateRules(t, RuleNOAUTH))
	fs := findingsOf(res, RuleNOAUTH)
	if len(fs) != 1 || fs[0].Confidence != finding.ConfMedium {
		t.Fatalf("matrix forbids anonymous: want 1 medium finding, got %+v", res.Findings)
	}
}

// An explicit matrix entry that allows anonymous access declares the
// endpoint public: identifiers in the anonymous response are then intended
// (a public user directory) and must not be reported as missing auth.
func TestNOAUTHMatrixAllowsAnonymous(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"name": "Alice", "email": "alice@example.com"})
	})
	cfg := testConfig(api.URL)
	cfg.Matrix = map[string]config.MatrixRule{"GET /users/me/profile": {Allow: []string{"anon", "user", "admin"}}}
	res := runScan(t, api, cfg, []spec.Endpoint{epProfile}, templateRules(t, RuleNOAUTH))
	if fs := findingsOf(res, RuleNOAUTH); len(fs) != 0 {
		t.Fatalf("matrix allows anonymous: want no NOAUTH finding, got %+v", fs)
	}

	// A matrix entry for another endpoint changes nothing.
	cfg.Matrix = map[string]config.MatrixRule{"GET /orders/**": {Allow: []string{"anon"}}}
	res = runScan(t, api, cfg, []spec.Endpoint{epProfile}, templateRules(t, RuleNOAUTH))
	if fs := findingsOf(res, RuleNOAUTH); len(fs) != 1 {
		t.Fatalf("unrelated matrix entry: want 1 NOAUTH finding, got %+v", res.Findings)
	}
}

func TestPhaseOrdering(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	cfg.Safety.Concurrency = 4
	eps := []spec.Endpoint{epDeleteOrder, epPatchOrder,
		{Method: "PUT", Path: "/orders/{id}", Params: []spec.Param{pathParam("id")}},
		epGetOrder, epProducts, {Method: "POST", Path: "/orders"}}
	runScan(t, api, cfg, eps, templateRules(t, RuleNOAUTH, RuleBOLARead))

	rank := map[string]int{"GET": 1, "POST": 1, "PUT": 2, "PATCH": 2, "DELETE": 4}
	last := 0
	for _, h := range api.Hits() {
		if rank[h.Method] < last {
			t.Fatalf("%s sent after a phase-%d request: %+v", h.Method, last, api.Hits())
		}
		last = rank[h.Method]
	}
	if last != 4 {
		t.Fatalf("no DELETE was sent: %+v", api.Hits())
	}
}

func TestHarvest(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		if r.URL.Path == "/me/orders" {
			if user == "alice" {
				writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{"id": "555"}}})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
			return
		}
		if user == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": orderID(r.URL.Path), "ownerId": "u-alice"})
	})
	cfg := testConfig(api.URL)
	for _, n := range []string{"alice", "bob"} {
		p := cfg.Profiles[n]
		delete(p.Owns, "id")
	}
	cfg.Harvest = []config.HarvestRule{
		{Endpoint: "GET /me/orders", Extract: map[string]string{"id": "$.items[*].id"}},
		{Endpoint: "DELETE /me/orders", Extract: map[string]string{"id": "$.id"}}, // destructive: ignored
	}
	epMeOrders := spec.Endpoint{Method: "GET", Path: "/me/orders", Secured: true}
	res := runScan(t, api, cfg, []spec.Endpoint{epGetOrder, epMeOrders}, templateRules(t, RuleBOLARead))

	var bobUsed bool
	for _, h := range api.Hits() {
		if h.Method == "DELETE" {
			t.Errorf("destructive harvest rule was sent: %+v", h)
		}
		if h.Who == "bob" && h.Path == "/orders/555" {
			bobUsed = true
		}
	}
	if !bobUsed {
		t.Fatalf("harvested id 555 not used by attacker: %+v", api.Hits())
	}
	if findPair(findingsOf(res, RuleBOLARead), "alice", "bob") == nil {
		t.Errorf("want finding with harvested id, got %+v", res.Findings)
	}
}

func TestDryRunNoNetwork(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	cfg := testConfig(api.URL)
	plan, err := DryRun(RunOptions{
		Config:    cfg,
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epDeleteOrder, epGetOrder, epPatchOrder}},
		Rules:     templateRules(t),
	})
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if n := len(api.Hits()); n != 0 {
		t.Fatalf("dry run sent %d requests", n)
	}
	if len(plan) == 0 {
		t.Fatal("empty plan")
	}
	var sawDestructive, sawSafe bool
	for _, p := range plan {
		want := p.Method == "DELETE" || p.Method == "PUT" || p.Method == "PATCH"
		if p.Destructive != want {
			t.Errorf("Destructive wrong for %+v", p)
		}
		sawDestructive = sawDestructive || p.Destructive
		sawSafe = sawSafe || !p.Destructive
		if p.RuleID == "" || p.Endpoint == "" || p.Step == "" || p.Profile == "" || p.Path == "" {
			t.Errorf("incomplete planned request %+v", p)
		}
	}
	if !sawDestructive || !sawSafe {
		t.Errorf("plan lacks destructive/safe mix: %+v", plan)
	}
	// phase order: GET endpoint planned before PATCH before DELETE.
	first := map[string]int{}
	for i, p := range plan {
		if _, ok := first[p.Endpoint]; !ok {
			first[p.Endpoint] = i
		}
	}
	if first["GET /orders/{id}"] >= first["PATCH /orders/{id}"] || first["PATCH /orders/{id}"] >= first["DELETE /orders/{id}"] {
		t.Errorf("plan not in phase order: %v", first)
	}
	// the admin step of BFLA with skipDestructive is never planned for DELETE.
	for _, p := range plan {
		if p.RuleID == RuleBOLARead && p.Endpoint != "GET /orders/{id}" {
			t.Errorf("BOLA read planned for %s", p.Endpoint)
		}
	}
}

func TestDeterministic(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	cfg := testConfig(api.URL)
	cfg.Safety.Concurrency = 8
	eps := []spec.Endpoint{epGetOrder, epProducts, epProfile, epAdminUsers}
	ids := func() ([]string, []finding.MatrixCell) {
		res := runScan(t, api, cfg, eps, templateRules(t))
		var out []string
		for _, f := range res.Findings {
			out = append(out, f.ID)
		}
		return out, res.Matrix
	}
	a, ma := ids()
	b, mb := ids()
	if len(a) == 0 {
		t.Fatal("expected findings")
	}
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("finding IDs differ:\n%v\n%v", a, b)
	}
	if len(ma) != len(mb) {
		t.Fatalf("matrix size differs")
	}
	for i := range ma {
		if ma[i] != mb[i] {
			t.Fatalf("matrix differs at %d: %+v vs %+v", i, ma[i], mb[i])
		}
	}
	if !sort.SliceIsSorted(ma, func(i, j int) bool {
		if ma[i].Endpoint != ma[j].Endpoint {
			return ma[i].Endpoint < ma[j].Endpoint
		}
		return ma[i].Profile < ma[j].Profile
	}) {
		t.Errorf("matrix not sorted by endpoint, profile: %+v", ma)
	}
}

func TestNewChecks(t *testing.T) {
	if _, err := NewChecks([]rules.Rule{{ID: "AD-NOPE-1", Kind: "nope"}}); err == nil {
		t.Error("want error for kinds without a registered check")
	}
	cs, err := NewChecks(templateRules(t))
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	if len(cs) != 4 || cs[0].Rule().ID == "" {
		t.Errorf("checks = %d", len(cs))
	}

	registry["fake"] = func(r *rules.Rule) Check { return &templateCheck{rule: r} }
	defer delete(registry, "fake")
	if cs, err := NewChecks([]rules.Rule{{ID: "AD-FAKE-1", Kind: "fake"}}); err != nil || len(cs) != 1 {
		t.Errorf("registered kind: %v %d", err, len(cs))
	}
}

func TestPhase(t *testing.T) {
	c := &templateCheck{rule: &rules.Rule{}}
	for m, want := range map[string]int{"GET": 1, "HEAD": 1, "OPTIONS": 1, "POST": 1, "PUT": 2, "PATCH": 2, "DELETE": 4} {
		if got := c.Phase(spec.Endpoint{Method: m}); got != want {
			t.Errorf("Phase(%s) = %d, want %d", m, got, want)
		}
	}
}

func TestApplies(t *testing.T) {
	yes, no := true, false
	env := &Env{Config: &config.Config{Matrix: map[string]config.MatrixRule{"/staff/**": {Allow: []string{"admin"}}}}}
	cases := []struct {
		name string
		a    rules.Applies
		ep   spec.Endpoint
		want bool
	}{
		{"empty applies all", rules.Applies{}, epGetOrder, true},
		{"method match", rules.Applies{Methods: []string{"get"}}, epGetOrder, true},
		{"method miss", rules.Applies{Methods: []string{"POST"}}, epGetOrder, false},
		{"param yes", rules.Applies{PathHasParam: &yes}, epGetOrder, true},
		{"param no", rules.Applies{PathHasParam: &no}, epGetOrder, false},
		{"admin by matrix", rules.Applies{AdminFunction: &yes}, spec.Endpoint{Method: "GET", Path: "/staff/x"}, true},
		{"admin miss", rules.Applies{AdminFunction: &yes}, epGetOrder, false},
		{"paths hit", rules.Applies{Paths: []string{"/x", "/orders/*"}}, epGetOrder, true},
		{"paths miss", rules.Applies{Paths: []string{"/users/**"}}, epGetOrder, false},
		{"requires body miss", rules.Applies{RequiresBody: true}, epGetOrder, false},
		{"requires body hit", rules.Applies{RequiresBody: true}, epPatchOrder, true},
	}
	for _, tc := range cases {
		c := &templateCheck{rule: &rules.Rule{Applies: tc.a}}
		if got := c.Applies(tc.ep, env); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestBindingsAndUnboundSingleRole(t *testing.T) {
	// no anonymous and no admin profile: BOLA still runs, anon step unsent.
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, user string) {
		if strings.HasPrefix(r.URL.Path, "/admin/") && user != "" {
			adminUsers(w, r, user)
			return
		}
		unprotectedOrders(w, r, user)
	})
	cfg := testConfig(api.URL)
	delete(cfg.Profiles, "anon")
	delete(cfg.Profiles, "admin")
	res := runScan(t, api, cfg, []spec.Endpoint{epGetOrder, epAdminUsers}, templateRules(t, RuleBOLARead, RuleBFLA))
	f := findPair(findingsOf(res, RuleBOLARead), "alice", "bob")
	if f == nil {
		t.Fatalf("want BOLA with unbound anonymous, got %+v", res.Findings)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("evidence = %d, want 2 (anon unsent)", len(f.Evidence))
	}
	// BFLA: admin unbound -> victim name empty, attackers alice and bob.
	if fs := findingsOf(res, RuleBFLA); len(fs) != 2 || fs[0].Victim != "" {
		t.Errorf("BFLA findings = %+v", fs)
	}
}

func TestSelfAndOtherUserWithoutOwner(t *testing.T) {
	r := rules.Rule{ID: "AD-TEST-001", Name: "self probe", Severity: "low", Steps: []rules.Step{
		{Name: "me", As: "self", Use: "self"},
		{Name: "peer", As: "other_user", Use: "self"},
	}, Match: "me.ok && peer.ok && peer.headers['content-type'] != '' && me.json != nil"}
	if err := rules.Validate(&r); err != nil {
		t.Fatal(err)
	}
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epProducts}, []rules.Rule{r})
	// self ∈ {admin, alice, bob}; other_user without an owner = any other non-anonymous profile.
	if len(res.Findings) != 6 {
		t.Fatalf("want 6 findings (3 self x 2 others), got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestNetworkErrorObservation(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	cfg := testConfig(api.URL)
	client := newTestClient(t, api, false)
	api.Close() // connection refused from now on
	res, err := Run(context.Background(), RunOptions{
		Config:    cfg,
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules:     templateRules(t, RuleNOAUTH),
		Client:    client,
	})
	if err != nil {
		t.Fatalf("network errors must not fail the run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
	var sawErr bool
	for _, c := range res.Matrix {
		if c.Outcome == finding.Errored {
			sawErr = true
		}
	}
	if !sawErr || res.Stats.Errors == 0 {
		t.Errorf("want error cells and error stats: %+v %+v", res.Matrix, res.Stats)
	}
}

func TestOutOfScopeIsSkipped(t *testing.T) {
	api := newAPI(t, unprotectedOrders)
	other := newAPI(t, unprotectedOrders)
	cfg := testConfig(other.URL) // base URL points outside the allow list
	res := runScan(t, api, cfg, []spec.Endpoint{epProducts}, templateRules(t, RuleNOAUTH))
	if len(other.Hits()) != 0 {
		t.Fatal("out-of-scope host was contacted")
	}
	for _, c := range res.Matrix {
		if c.Outcome != finding.Skipped {
			t.Errorf("cell = %+v, want skipped", c)
		}
	}
}

func TestMatrixOutcomes(t *testing.T) {
	obs := []Observation{
		{Endpoint: "GET /a", Profile: "alice", Sent: false},
		{Endpoint: "GET /a", Profile: "alice", Sent: true, Status: 200},
		{Endpoint: "GET /a", Profile: "bob", Sent: true, Status: 403},
		{Endpoint: "GET /a", Profile: "bob", Sent: true, Status: 200},
		{Endpoint: "GET /a", Profile: "carol", Sent: true, Status: 500},
		{Endpoint: "GET /a", Profile: "dave", Err: "boom"},
		{Endpoint: "GET /a", Profile: "erin", Sent: true, Status: 400},
		{Endpoint: "GET /a", Profile: "frank", Sent: true, Status: 429},
		{Endpoint: "GET /ghost", Profile: "alice", Sent: true, Status: 200},
	}
	fs := []finding.Finding{{Method: "GET", Path: "/a", Attacker: "alice"}}
	cells := buildMatrix(obs, fs, map[string]bool{"GET /a": true})
	want := map[string]finding.Outcome{"alice": finding.Unexpected, "bob": finding.Denied,
		"carol": finding.Errored, "dave": finding.Errored, "erin": finding.Denied,
		"frank": finding.Errored}
	if len(cells) != len(want) {
		t.Fatalf("cells = %+v", cells)
	}
	for _, c := range cells {
		if want[c.Profile] != c.Outcome {
			t.Errorf("%s = %s, want %s", c.Profile, c.Outcome, want[c.Profile])
		}
	}
}

func TestMergeFindings(t *testing.T) {
	fs := mergeFindings([]finding.Finding{
		{ID: "x", Confidence: finding.ConfMedium},
		{ID: "y", Confidence: finding.ConfLow},
		{ID: "x", Confidence: finding.ConfHigh},
	})
	if len(fs) != 2 || fs[0].Confidence != finding.ConfHigh {
		t.Errorf("merged = %+v", fs)
	}
}

func TestRunValidation(t *testing.T) {
	inv := &spec.Inventory{}
	cfg := testConfig("http://x")
	cases := []RunOptions{
		{Inventory: inv},
		{Config: cfg},
		{Config: cfg, Inventory: inv}, // no client, no sender
		{Config: cfg, Inventory: inv, Sender: errSender{}, Rules: []rules.Rule{{ID: "AD-X-1", Kind: "nope"}}},
	}
	for i, o := range cases {
		if _, err := Run(context.Background(), o); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	if _, err := DryRun(RunOptions{Config: cfg}); err == nil {
		t.Error("DryRun without inventory: want error")
	}
	if _, err := DryRun(RunOptions{Config: cfg, Inventory: inv, Rules: []rules.Rule{{ID: "AD-X-1", Kind: "nope"}}}); err == nil {
		t.Error("DryRun with unknown kind: want error")
	}
}

type errSender struct{ err error }

func (s errSender) Send(context.Context, *identity.Profile, string, planner.Request) (*transport.Response, error) {
	if s.err == nil {
		return nil, errors.New("down")
	}
	return nil, s.err
}

func TestContextCancelFailsRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, RunOptions{
		Config:    testConfig("http://x"),
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules:     templateRules(t, RuleNOAUTH),
		Sender:    errSender{err: context.Canceled},
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if res == nil {
		t.Error("want a (partial) result alongside the cancellation error")
	}
}

func TestSenderDeadlineErrorWithoutCallerCancelIsProbeFailure(t *testing.T) {
	// An error matching context.DeadlineExceeded (e.g. http.Client.Timeout)
	// while the caller's ctx is alive is an ordinary failed probe.
	res, err := Run(context.Background(), RunOptions{
		Config:    testConfig("http://x"),
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules:     templateRules(t, RuleNOAUTH),
		Sender:    errSender{err: context.DeadlineExceeded},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Matrix) == 0 {
		t.Fatal("no cells")
	}
	for _, c := range res.Matrix {
		if c.Outcome != finding.Errored {
			t.Errorf("cell = %+v, want error", c)
		}
	}
}

func TestRequestTimeoutDoesNotAbortRun(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.URL.Path == "/slow" {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": "Alice", "email": "alice@example.com"})
	})
	client, err := transport.New(transport.Options{AllowHosts: []string{api.host()}, Rate: 1000, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), RunOptions{
		Config:    testConfig(api.URL),
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{{Method: "GET", Path: "/slow"}, epProfile}},
		Rules:     templateRules(t, RuleNOAUTH),
		Client:    client,
	})
	if err != nil {
		t.Fatalf("a timed-out request must not abort the run: %v", err)
	}
	if len(findingsOf(res, RuleNOAUTH)) != 1 {
		t.Errorf("finding on the healthy endpoint lost: %+v", res.Findings)
	}
	var slowCells int
	for _, c := range res.Matrix {
		if c.Endpoint == "GET /slow" {
			slowCells++
			if c.Outcome != finding.Errored {
				t.Errorf("slow cell = %+v, want error", c)
			}
		}
	}
	if slowCells == 0 || res.Stats.Errors == 0 {
		t.Errorf("want errored slow cells and error stats: %+v %+v", res.Matrix, res.Stats)
	}
}

func TestCancelReturnsPartialResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.Method == http.MethodPut {
			cancel() // the user hits Ctrl-C while phase 2 runs
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": "Alice", "email": "alice@example.com"})
	})
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res, err := Run(ctx, RunOptions{
		Config:    cfg,
		Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epProfile, {Method: "PUT", Path: "/users/me/profile"}}},
		Rules:     templateRules(t, RuleNOAUTH),
		Client:    newTestClient(t, api, true),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res == nil {
		t.Fatal("want partial result")
	}
	if len(res.Findings) != 1 || res.Findings[0].Method != "GET" {
		t.Errorf("phase-1 finding not kept: %+v", res.Findings)
	}
	if res.Stats.Requests == 0 || len(res.Matrix) == 0 || res.FinishedAt.IsZero() {
		t.Errorf("partial result incomplete: stats %+v matrix %d", res.Stats, len(res.Matrix))
	}
}

func TestBuildErrorSkipsCombination(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"email": "alice@example.com"})
	})
	cfg := testConfig(api.URL)
	cfg.Bodies = map[string]any{"POST /orders": map[string]any{"qty": math.Inf(1)}} // not JSON-encodable
	res := runScan(t, api, cfg, []spec.Endpoint{{Method: "POST", Path: "/orders"}, epProfile}, templateRules(t, RuleNOAUTH))
	if len(findingsOf(res, RuleNOAUTH)) != 1 {
		t.Errorf("other endpoint's finding lost: %+v", res.Findings)
	}
	var errored bool
	for _, c := range res.Matrix {
		if c.Endpoint == "POST /orders" && c.Outcome == finding.Errored {
			errored = true
		}
	}
	if !errored {
		t.Errorf("want errored cell for unbuildable request: %+v", res.Matrix)
	}
}

func TestEvalErrorSkipsCombination(t *testing.T) {
	r := rules.Rule{ID: "AD-TEST-002", Name: "bad", Severity: "low",
		Steps: []rules.Step{{Name: "a", As: "any_user", Use: "any_user"}},
		Match: "a.json.missing.deeper == 1"}
	if err := rules.Validate(&r); err != nil {
		t.Fatal(err)
	}
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	cfg := testConfig(api.URL)
	client := newTestClient(t, api, false)
	res, err := Run(context.Background(), RunOptions{
		Config: cfg, Inventory: &spec.Inventory{Endpoints: []spec.Endpoint{epProducts}},
		Rules: []rules.Rule{r}, Client: client,
	})
	if err != nil {
		t.Fatalf("eval error must not abort the run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v", res.Findings)
	}
	checks, err := NewChecks([]rules.Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	out, err := checks[0].Run(context.Background(), epProducts, newEnv(cfg, NewSender(client), nil))
	if err != nil {
		t.Fatalf("check.Run: %v", err)
	}
	var sawErr bool
	for _, o := range out.Observations {
		if strings.Contains(o.Err, "AD-TEST-002") && o.Profile == "admin" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Errorf("want an errored observation for the eval failure: %+v", out.Observations)
	}
}

// failingCheck is a non-template check whose Run always fails.
type failingCheck struct{ templateCheck }

func (*failingCheck) Run(context.Context, spec.Endpoint, *Env) (Outcome, error) {
	return Outcome{}, errors.New("check bug")
}

func TestCheckErrorDoesNotAbortRun(t *testing.T) {
	registry["failing"] = func(r *rules.Rule) Check { return &failingCheck{templateCheck{rule: r}} }
	defer delete(registry, "failing")
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"email": "alice@example.com"})
	})
	rs := append(templateRules(t, RuleNOAUTH), rules.Rule{ID: "AD-FAIL-1", Kind: "failing"})
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epProducts}, rs)
	if len(findingsOf(res, RuleNOAUTH)) != 1 {
		t.Errorf("a failing check must not discard others' findings: %+v", res.Findings)
	}
}
