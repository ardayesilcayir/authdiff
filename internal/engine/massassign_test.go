package engine

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

var (
	epGetMe   = spec.Endpoint{Method: "GET", Path: "/me", Secured: true}
	epPatchMe = spec.Endpoint{Method: "PATCH", Path: "/me", Secured: true, Line: 40,
		Body: &spec.Body{ContentType: "application/json", Example: map[string]any{"name": "x"}, Fields: []string{"name"}}}
	epPostMe = spec.Endpoint{Method: "POST", Path: "/me", Secured: true,
		Body: &spec.Body{ContentType: "application/json", Example: map[string]any{"name": "x"}, Fields: []string{"name", "role"}}}
)

// userStore is a /me API. With bind, every key of a write is stored (mass
// assignment); otherwise only "name" is.
type userStore struct {
	mu    sync.Mutex
	users map[string]map[string]any
	bind  bool
	got   []map[string]any // bodies received by writes
}

func newUserStore(bind bool) *userStore {
	return &userStore{bind: bind, users: map[string]map[string]any{
		"alice": {"name": "alice", "role": "user"},
		"bob":   {"name": "bob", "role": "user"},
		"admin": {"name": "admin", "role": "admin"},
	}}
}

func (s *userStore) handle(w http.ResponseWriter, r *http.Request, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[user]
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, u)
	case http.MethodPatch, http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.got = append(s.got, body)
		for k, v := range body {
			if s.bind || k == "name" {
				u[k] = v
			}
		}
		writeJSON(w, http.StatusOK, u)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestMassAssignFinds(t *testing.T) {
	store := newUserStore(true)
	api := newAPI(t, store.handle)
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res := runScan(t, api, cfg, []spec.Endpoint{epGetMe, epPatchMe}, builtinRules(t, RuleMass))

	fs := findingsOf(res, RuleMass)
	f := findPair(fs, "alice", "alice")
	if f == nil {
		t.Fatalf("want AD-MASS-001 alice, got %+v", res.Findings)
	}
	if f.Confidence != finding.ConfHigh || f.Method != "PATCH" || f.Path != "/me" || f.Line != 40 {
		t.Errorf("finding = %+v", f)
	}
	if f.ID != finding.NewID(RuleMass, "PATCH", "/me", "alice", "alice") {
		t.Errorf("id = %s", f.ID)
	}
	for _, field := range []string{"role", "isAdmin", "is_admin", "ownerId"} {
		if !strings.Contains(f.Description, field) {
			t.Errorf("description %q lacks %s", f.Description, field)
		}
	}
	if len(f.Evidence) != 3 || f.Evidence[0].Step != "before" || f.Evidence[1].Step != "inject" || f.Evidence[2].Step != "after" {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
	// alice's injected ownerId is the first other non-anonymous profile's userId.
	// admin has no userId, so bob's is used.
	var aliceBody map[string]any
	for _, b := range store.got {
		if b["name"] == "x" && aliceBody == nil {
			aliceBody = b
		}
	}
	if aliceBody["role"] != "admin" || aliceBody["isAdmin"] != true || aliceBody["is_admin"] != true {
		t.Errorf("injected body = %v", aliceBody)
	}
	if findPair(fs, "anon", "anon") != nil {
		t.Error("anonymous must not be tested")
	}
}

func TestMassAssignSilent(t *testing.T) {
	store := newUserStore(false)
	api := newAPI(t, store.handle)
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res := runScan(t, api, cfg, []spec.Endpoint{epGetMe, epPatchMe}, builtinRules(t, RuleMass))
	if fs := findingsOf(res, RuleMass); len(fs) != 0 {
		t.Fatalf("ignored fields must be silent, got %+v", fs)
	}
	if len(store.got) == 0 {
		t.Fatal("no write was sent")
	}
}

func TestMassAssignSkipsWithoutGET(t *testing.T) {
	store := newUserStore(true)
	api := newAPI(t, store.handle)
	cfg := testConfig(api.URL)
	cfg.Safety.AllowDestructive = true
	res := runScan(t, api, cfg, []spec.Endpoint{epPatchMe}, builtinRules(t, RuleMass))
	if len(api.Hits()) != 0 || len(res.Findings) != 0 {
		t.Fatalf("without a GET on the path nothing is sent: hits %v findings %+v", api.Hits(), res.Findings)
	}
}

func TestMassAssignSafeModeSkips(t *testing.T) {
	store := newUserStore(true)
	api := newAPI(t, store.handle)
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epGetMe, epPatchMe}, builtinRules(t, RuleMass))
	for _, h := range api.Hits() {
		if h.Method == http.MethodPatch {
			t.Fatal("safe mode must block PATCH")
		}
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	for _, c := range res.Matrix {
		if c.Endpoint == "PATCH /me" && c.Outcome != finding.Skipped {
			t.Errorf("blocked write cell = %+v", c)
		}
	}
}

// POST is not destructive; declared fields (role) are not injected, and a
// numeric userId is sent as a JSON number.
func TestMassAssignPostDeclaredAndNumericOwner(t *testing.T) {
	store := newUserStore(true)
	api := newAPI(t, store.handle)
	cfg := testConfig(api.URL)
	bob := cfg.Profiles["bob"]
	bob.Owns = map[string][]string{"userId": {"42"}}
	cfg.Profiles["bob"] = bob
	res := runScan(t, api, cfg, []spec.Endpoint{epGetMe, epPostMe}, builtinRules(t, RuleMass))
	var aliceBody map[string]any
	for _, b := range store.got {
		if _, ok := b["ownerId"]; ok && b["ownerId"] == float64(42) {
			aliceBody = b
		}
	}
	if aliceBody == nil {
		t.Fatalf("want a write with numeric ownerId 42, got %v", store.got)
	}
	if aliceBody["role"] != "x" && aliceBody["role"] != nil {
		t.Errorf("declared field role must not be injected: %v", aliceBody)
	}
	f := findPair(findingsOf(res, RuleMass), "alice", "alice")
	if f == nil || !strings.HasSuffix(f.Description, "Persisted fields: isAdmin, is_admin, ownerId.") {
		t.Fatalf("want finding without role, got %+v", res.Findings)
	}
}

func TestMassAssignInjectedOwner(t *testing.T) {
	cfg := testConfig("http://x")
	env := newEnv(cfg, nil, nil)
	if got := injectedOwner(env, "alice"); got != "u-bob" {
		t.Errorf("alice -> %v, want u-bob", got)
	}
	if got := injectedOwner(env, "bob"); got != "u-alice" {
		t.Errorf("bob -> %v, want u-alice", got)
	}
	delete(cfg.Profiles, "bob")
	env = newEnv(cfg, nil, nil)
	if got := injectedOwner(env, "alice"); got != 999999 {
		t.Errorf("no other user -> %v (%T), want 999999", got, got)
	}
}

func TestMassAssignAppliesAndPlan(t *testing.T) {
	cfg := testConfig("http://x")
	env := newEnv(cfg, nil, nil)
	env.Endpoints = []spec.Endpoint{epGetMe, epPatchMe}
	cs, err := NewChecks(builtinRules(t, RuleMass))
	if err != nil {
		t.Fatal(err)
	}
	c := cs[0]
	if !c.Applies(epPatchMe, env) || c.Applies(epGetMe, env) || c.Phase(epPatchMe) != 2 {
		t.Error("applies/phase wrong")
	}
	xml := epPatchMe
	xml.Body = &spec.Body{ContentType: "application/xml", Fields: []string{"name"}}
	if c.Applies(xml, env) {
		t.Error("non-JSON body must not apply")
	}
	plan := c.Plan(epPatchMe, env)
	// 2 non-anonymous, non-admin profiles x (before, inject, after)
	if len(plan) != 6 || plan[1].Method != "PATCH" || !plan[1].Destructive || plan[0].Method != "GET" {
		t.Errorf("plan = %+v", plan)
	}
}
