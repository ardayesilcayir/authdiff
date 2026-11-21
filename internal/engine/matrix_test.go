package engine

import (
	"context"
	"net/http"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

func matrixRule(t *testing.T) *rules.Rule {
	t.Helper()
	rs := builtinRules(t, RuleMatrix)
	return &rs[0]
}

func adminOnlyConfig() *config.Config {
	cfg := testConfig("http://x")
	cfg.Matrix = map[string]config.MatrixRule{"GET /admin/**": {Allow: []string{"admin"}}}
	return cfg
}

func TestMatrixViolation(t *testing.T) {
	obs := []Observation{
		{Endpoint: "GET /admin/users", Profile: "admin", Sent: true, Status: 200},
		{Endpoint: "GET /admin/users", Profile: "bob", Sent: true, Status: 200, OwnIDs: true,
			Exchange: &finding.Exchange{Step: "attacker", Profile: "bob"}},
		{Endpoint: "GET /admin/users", Profile: "bob", Sent: true, Status: 200},
		{Endpoint: "GET /admin/users", Profile: "alice", Sent: true, Status: 403},
		{Endpoint: "GET /admin/users", Profile: "anon", Err: "boom"},
		{Endpoint: "GET /orders/{id}", Profile: "bob", Sent: true, Status: 200},
	}
	fs := EvaluateMatrix(adminOnlyConfig(), obs, nil, matrixRule(t))
	if len(fs) != 1 {
		t.Fatalf("want one finding for bob, got %+v", fs)
	}
	f := fs[0]
	if f.RuleID != RuleMatrix || f.Victim != "matrix" || f.Attacker != "bob" || f.Method != "GET" || f.Path != "/admin/users" {
		t.Errorf("finding = %+v", f)
	}
	if f.ID != finding.NewID(RuleMatrix, "GET", "/admin/users", "matrix", "bob") || f.Severity != finding.High || f.Title == "" {
		t.Errorf("finding meta = %+v", f)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Profile != "bob" {
		t.Errorf("evidence = %+v", f.Evidence)
	}
}

func TestMatrixDedup(t *testing.T) {
	obs := []Observation{{Endpoint: "GET /admin/users", Profile: "bob", Sent: true, Status: 200}}
	existing := []finding.Finding{{RuleID: RuleBFLA, Method: "GET", Path: "/admin/users", Victim: "admin", Attacker: "bob"}}
	if fs := EvaluateMatrix(adminOnlyConfig(), obs, existing, matrixRule(t)); len(fs) != 0 {
		t.Fatalf("existing BFLA finding must suppress the matrix finding: %+v", fs)
	}
}

func TestMatrixOwnerAllowed(t *testing.T) {
	cfg := testConfig("http://x")
	cfg.Matrix = map[string]config.MatrixRule{"/orders/*": {Allow: []string{"owner"}}}
	obs := []Observation{
		{Endpoint: "GET /orders/{id}", Profile: "alice", Sent: true, Status: 200, OwnIDs: true},
		{Endpoint: "GET /orders/{id}", Profile: "bob", Sent: true, Status: 200, OwnIDs: false},
	}
	fs := EvaluateMatrix(cfg, obs, nil, matrixRule(t))
	if len(fs) != 1 || fs[0].Attacker != "bob" {
		t.Fatalf("owner allowed, non-owner flagged: %+v", fs)
	}
	if fs := EvaluateMatrix(testConfig("http://x"), obs, nil, matrixRule(t)); len(fs) != 0 {
		t.Errorf("no matrix configured must be silent: %+v", fs)
	}
}

func TestMatrixRoleAllowed(t *testing.T) {
	cfg := testConfig("http://x")
	cfg.Matrix = map[string]config.MatrixRule{"GET /reports": {Allow: []string{"user", "anon"}}}
	obs := []Observation{
		{Endpoint: "GET /reports", Profile: "alice", Sent: true, Status: 200},
		{Endpoint: "GET /reports", Profile: "anon", Sent: true, Status: 200},
		{Endpoint: "GET /reports", Profile: "admin", Sent: true, Status: 200},
		{Endpoint: "garbage", Profile: "admin", Sent: true, Status: 200},
	}
	fs := EvaluateMatrix(cfg, obs, nil, matrixRule(t))
	if len(fs) != 1 || fs[0].Attacker != "admin" {
		t.Fatalf("role and name allow: %+v", fs)
	}
}

// Through Run: only owners can read their orders, but the matrix allows
// only admin and support, so every owner's 200 is a violation; with "owner"
// allowed none is.
func TestMatrixRun(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request, user string) {
		id := orderID(r.URL.Path)
		if orders[id] != user {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, orderBody(id))
	}
	api := newAPI(t, h)
	cfg := testConfig(api.URL)
	// "support" keeps this from being an admin function, so BOLA still runs.
	cfg.Matrix = map[string]config.MatrixRule{"GET /orders/*": {Allow: []string{"admin", "support"}}}
	rs := append(templateRules(t, RuleBOLARead), builtinRules(t, RuleMatrix)...)
	res := runScan(t, api, cfg, []spec.Endpoint{epGetOrder}, rs)
	fs := findingsOf(res, RuleMatrix)
	if len(fs) != 2 || findPair(fs, "matrix", "alice") == nil || findPair(fs, "matrix", "bob") == nil {
		t.Fatalf("want matrix findings for alice and bob, got %+v", res.Findings)
	}
	if fs[0].Line != 12 {
		t.Errorf("line = %d, want 12 from the inventory", fs[0].Line)
	}
	cells := map[string]finding.Outcome{}
	for _, c := range res.Matrix {
		cells[c.Profile] = c.Outcome
	}
	if cells["alice"] != finding.Unexpected {
		t.Errorf("alice cell = %s", cells["alice"])
	}

	api2 := newAPI(t, h)
	cfg2 := testConfig(api2.URL)
	cfg2.Matrix = map[string]config.MatrixRule{"GET /orders/*": {Allow: []string{"owner"}}}
	res2 := runScan(t, api2, cfg2, []spec.Endpoint{epGetOrder}, rs)
	if fs := findingsOf(res2, RuleMatrix); len(fs) != 0 {
		t.Fatalf("owners are allowed: %+v", fs)
	}
}

func TestMatrixCheckNeverRunsPerEndpoint(t *testing.T) {
	cs, err := NewChecks(builtinRules(t, RuleMatrix))
	if err != nil {
		t.Fatal(err)
	}
	env := newEnv(adminOnlyConfig(), nil, nil)
	if cs[0].Applies(epGetOrder, env) || cs[0].Plan(epGetOrder, env) != nil {
		t.Error("matrix check is post-run only")
	}
	if out, err := cs[0].Run(context.Background(), epGetOrder, env); err != nil || len(out.Findings) != 0 {
		t.Errorf("Run = %+v %v", out, err)
	}
	_ = cs[0].Phase(epGetOrder)
}
