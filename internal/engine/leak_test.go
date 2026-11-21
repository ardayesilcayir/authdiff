package engine

import (
	"net/http"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

var epUsers = spec.Endpoint{Method: "GET", Path: "/users", Secured: true, Line: 7}

func leakyUsers(w http.ResponseWriter, _ *http.Request, user string) {
	if user == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, []any{
		map[string]any{"id": 1, "email": "a@x", "passwordHash": "$2b$...", "profile": map[string]any{"apiKey": "k"}},
		map[string]any{"id": 2, "email": "b@x", "passwordHash": "$2b$..."},
	})
}

func TestLeakFinds(t *testing.T) {
	api := newAPI(t, leakyUsers)
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{epUsers}, builtinRules(t, RuleLeak))
	fs := findingsOf(res, RuleLeak)
	if len(fs) != 1 {
		t.Fatalf("want 1 leak finding, got %+v", res.Findings)
	}
	f := fs[0]
	// any_user is the first non-anonymous profile by name.
	if f.Victim != "admin" || f.Attacker != "admin" || f.Method != "GET" || f.Line != 7 || f.Confidence != finding.ConfMedium {
		t.Errorf("finding = %+v", f)
	}
	if want := "Sensitive fields: apiKey, passwordHash."; len(f.Description) < len(want) || f.Description[len(f.Description)-len(want):] != want {
		t.Errorf("description = %q", f.Description)
	}
	if len(f.Evidence) != 1 {
		t.Errorf("evidence = %+v", f.Evidence)
	}
}

func TestLeakSilentWhenDeclared(t *testing.T) {
	api := newAPI(t, leakyUsers)
	ep := epUsers
	ep.ResponseFields = []string{"apiKey", "email", "id", "passwordHash", "profile"}
	res := runScan(t, api, testConfig(api.URL), []spec.Endpoint{ep}, builtinRules(t, RuleLeak))
	if len(res.Findings) != 0 {
		t.Fatalf("declared fields must be silent, got %+v", res.Findings)
	}
}

func TestLeakSilentOnErrorsAndNonJSON(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if r.URL.Path == "/html" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>token password</html>"))
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]any{"token": "x"})
	})
	eps := []spec.Endpoint{{Method: "GET", Path: "/html"}, {Method: "GET", Path: "/denied"}}
	res := runScan(t, api, testConfig(api.URL), eps, builtinRules(t, RuleLeak))
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestLeakKeys(t *testing.T) {
	got := sensitiveKeys([]byte(`{"a":{"Token":1,"tokens":[{"ssn":"x"}]},"secret_hash":"h","ok":1}`), []string{"ssn"})
	want := []string{"Token", "secret_hash"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("keys = %v, want %v", got, want)
	}
	if sensitiveKeys([]byte(`not json`), nil) != nil {
		t.Error("non-JSON yields nothing")
	}
}

func TestLeakAppliesAndPlan(t *testing.T) {
	cs, err := NewChecks(builtinRules(t, RuleLeak))
	if err != nil {
		t.Fatal(err)
	}
	env := newEnv(testConfig("http://x"), nil, nil)
	if !cs[0].Applies(epUsers, env) || cs[0].Applies(epPatchOrder, env) || cs[0].Phase(epUsers) != 1 {
		t.Error("applies/phase")
	}
	p := cs[0].Plan(epGetOrder, env)
	// any_user prefers a profile owning the path IDs: alice.
	if len(p) != 1 || p[0].Profile != "alice" || p[0].Path != "/orders/101" {
		t.Errorf("plan = %+v", p)
	}
}
