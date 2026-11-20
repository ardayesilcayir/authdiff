package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// hit is one request seen by a mini API.
type hit struct {
	Method, Path, Who string
}

// miniAPI is an httptest server that records every request it receives.
type miniAPI struct {
	*httptest.Server
	mu   sync.Mutex
	hits []hit
}

var tokens = map[string]string{
	"Bearer tok-alice": "alice",
	"Bearer tok-bob":   "bob",
	"Bearer tok-admin": "admin",
}

// who returns the profile name behind the request's credentials ("" if anonymous).
func who(r *http.Request) string { return tokens[r.Header.Get("Authorization")] }

func newAPI(t *testing.T, h func(w http.ResponseWriter, r *http.Request, user string)) *miniAPI {
	t.Helper()
	api := &miniAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := who(r)
		api.mu.Lock()
		api.hits = append(api.hits, hit{Method: r.Method, Path: r.URL.Path, Who: u})
		api.mu.Unlock()
		h(w, r, u)
	}))
	t.Cleanup(api.Close)
	return api
}

func (a *miniAPI) Hits() []hit {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]hit(nil), a.hits...)
}

func (a *miniAPI) host() string { return strings.TrimPrefix(a.URL, "http://") }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func requestID() string { return fmt.Sprintf("req-%d", rand.Int63()) }

// testConfig has alice and bob (role user, each owning an order), an admin and
// an anonymous profile.
func testConfig(baseURL string) *config.Config {
	c := &config.Config{
		Target: config.Target{BaseURL: baseURL},
		Profiles: map[string]config.Profile{
			"alice": {Role: "user", Auth: config.Auth{Type: "bearer", Token: "tok-alice"},
				Owns:        map[string][]string{"id": {"101"}, "userId": {"u-alice"}},
				Identifiers: []string{"alice@example.com"}},
			"bob": {Role: "user", Auth: config.Auth{Type: "bearer", Token: "tok-bob"},
				Owns:        map[string][]string{"id": {"201"}, "userId": {"u-bob"}},
				Identifiers: []string{"bob@example.com"}},
			"admin": {Role: "admin", Auth: config.Auth{Type: "bearer", Token: "tok-admin"}},
			"anon":  {Role: "anonymous", Auth: config.Auth{Type: "none"}},
		},
	}
	c.ApplyDefaults()
	return c
}

// templateRules returns the built-in template rules, restricted to ids if given.
func templateRules(t *testing.T, ids ...string) []rules.Rule {
	t.Helper()
	all, err := rules.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []rules.Rule
	for _, r := range all {
		if r.Kind != rules.KindTemplate {
			continue
		}
		if len(want) > 0 && !want[r.ID] {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		t.Fatalf("no rules selected for %v", ids)
	}
	return out
}

func newTestClient(t *testing.T, api *miniAPI, allowDestructive bool) *transport.Client {
	t.Helper()
	c, err := transport.New(transport.Options{
		AllowHosts:       []string{api.host()},
		Rate:             1000,
		Retries:          0,
		AllowDestructive: allowDestructive,
	})
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	return c
}

func runScan(t *testing.T, api *miniAPI, cfg *config.Config, eps []spec.Endpoint, rs []rules.Rule) *finding.Result {
	t.Helper()
	res, err := Run(context.Background(), RunOptions{
		Config:    cfg,
		Inventory: &spec.Inventory{Endpoints: eps, SpecPath: "openapi.yaml"},
		Rules:     rs,
		Client:    newTestClient(t, api, cfg.Safety.AllowDestructive),
		Version:   "test",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func findingsOf(res *finding.Result, ruleID string) []finding.Finding {
	var out []finding.Finding
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func findPair(fs []finding.Finding, victim, attacker string) *finding.Finding {
	for i := range fs {
		if fs[i].Victim == victim && fs[i].Attacker == attacker {
			return &fs[i]
		}
	}
	return nil
}

func pathParam(name string) spec.Param { return spec.Param{Name: name, In: "path", Required: true} }

var (
	epGetOrder   = spec.Endpoint{Method: "GET", Path: "/orders/{id}", Secured: true, Params: []spec.Param{pathParam("id")}, Line: 12}
	epPatchOrder = spec.Endpoint{Method: "PATCH", Path: "/orders/{id}", Secured: true, Params: []spec.Param{pathParam("id")},
		Body: &spec.Body{ContentType: "application/json", Example: map[string]any{"item": "pen"}}, Line: 20}
	epDeleteOrder = spec.Endpoint{Method: "DELETE", Path: "/orders/{id}", Secured: true, Params: []spec.Param{pathParam("id")}, Line: 30}
)

// orders is the seeded order store: id -> owner.
var orders = map[string]string{"101": "alice", "201": "bob"}

func orderBody(id string) map[string]any {
	return map[string]any{"id": id, "ownerId": "u-" + orders[id], "item": "book", "requestId": requestID()}
}

// orderID returns the {id} of /orders/{id}, or "".
func orderID(p string) string {
	if !strings.HasPrefix(p, "/orders/") {
		return ""
	}
	return strings.TrimPrefix(p, "/orders/")
}
