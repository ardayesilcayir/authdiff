package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

const (
	runAliceToken = "alice-ui-run-token-1111"
	runBobToken   = "bob-ui-run-token-2222" //nolint:gosec // G101: fake test token
	runProject    = "mini"
)

const runSpec = `openapi: 3.0.3
info: { title: mini, version: "1" }
components:
  securitySchemes:
    bearer: { type: http, scheme: bearer }
security: [ { bearer: [] } ]
paths:
  /orders/{orderId}:
    get:
      operationId: getOrder
      parameters:
        - { name: orderId, in: path, required: true, schema: { type: string } }
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: { type: string }
                  owner: { type: string }
                  total: { type: number }
    delete:
      operationId: deleteOrder
      parameters:
        - { name: orderId, in: path, required: true, schema: { type: string } }
      responses:
        "204": { description: deleted }
`

// runAPI serves /orders/{id} to any authenticated user (a BOLA bug). When
// gated, requests after the first `free` ones wait until release is closed
// or the client gives up.
type runAPI struct {
	*httptest.Server
	hits    atomic.Int64
	free    int64
	gated   bool
	release chan struct{}
	once    sync.Once
}

func newRunAPI(t *testing.T, gated bool, free int64) *runAPI {
	t.Helper()
	orders := map[string]map[string]any{
		"101": {"id": "101", "owner": "alice@example.com", "total": 10},
		"201": {"id": "201", "owner": "bob@example.com", "total": 20},
	}
	api := &runAPI{gated: gated, free: free, release: make(chan struct{})}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := api.hits.Add(1); api.gated && n > api.free {
			select {
			case <-api.release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+runAliceToken && auth != "Bearer "+runBobToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"login required"}`))
			return
		}
		o, ok := orders[strings.TrimPrefix(r.URL.Path, "/orders/")]
		if !ok || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(o)
	}))
	t.Cleanup(func() {
		api.open()
		api.Close()
	})
	return api
}

func (a *runAPI) open() { a.once.Do(func() { close(a.release) }) }

// runFixture saves a project pointing at api with an uploaded spec; with
// secrets, the tokens of alice and bob are put in memory.
func runFixture(t *testing.T, s *Server, api *runAPI, destructive, secrets bool) *Project {
	t.Helper()
	p := &Project{
		Name:         runProject,
		BaseURL:      api.URL,
		AllowHosts:   []string{strings.TrimPrefix(api.URL, "http://")},
		Acknowledged: true,
		Profiles: []ProfileDef{
			{Name: "alice", Role: "user", AuthType: "bearer", Owns: map[string][]string{"orderId": {"101"}}, Identifiers: []string{"alice@example.com"}},
			{Name: "bob", Role: "user", AuthType: "bearer", Owns: map[string][]string{"orderId": {"201"}}, Identifiers: []string{"bob@example.com"}},
			{Name: "anonymous", Role: "anonymous", AuthType: "none"},
		},
		Safety: SafetyDef{Rate: 1000, Concurrency: 1, AllowDestructive: destructive},
		Step:   "plan",
	}
	if err := s.store.Save(p); err != nil {
		t.Fatal(err)
	}
	file, err := s.store.SaveSpec(p.Name, strings.NewReader(runSpec), ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.SpecFile = file
	if err := s.store.Save(p); err != nil {
		t.Fatal(err)
	}
	if secrets {
		s.secrets.Set(p.Name, "alice", Secret{Token: runAliceToken})
		s.secrets.Set(p.Name, "bob", Secret{Token: runBobToken})
	}
	return p
}

// runServer is a test server whose scans are stopped before the temp dirs
// are removed.
func runServer(t *testing.T, o Options) *Server {
	t.Helper()
	s := testServer(t, o)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.runs.Shutdown(ctx)
	})
	return s
}

var runURLRe = regexp.MustCompile(`^/p/` + runProject + `/runs/(\d{8}-\d{6}(?:-\d+)?)$`)

// startScan posts the scan form and returns the run ID it redirects to.
func startScan(t *testing.T, s *Server) string {
	t.Helper()
	w := do(s, postForm(s, "/p/"+runProject+"/scan", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("scan: status %d, body %s", w.Code, w.Body.String())
	}
	m := runURLRe.FindStringSubmatch(w.Header().Get("Location"))
	if m == nil {
		t.Fatalf("scan redirected to %q", w.Header().Get("Location"))
	}
	return m[1]
}

func waitRun(t *testing.T, s *Server, id string) {
	t.Helper()
	select {
	case <-s.runs.doneCh(id):
	case <-time.After(20 * time.Second):
		t.Fatalf("run %s did not finish", id)
	}
}

func readResult(t *testing.T, s *Server, id string) *finding.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.store.RunsDir(runProject), id, "results.json")) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal(err)
	}
	var r finding.Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

type sseEvent struct {
	Type string
	Data string
}

// parseSSE splits an event stream into events; comments are skipped.
func parseSSE(t *testing.T, body string) []sseEvent {
	t.Helper()
	var out []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.Type != "" {
				out = append(out, cur)
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event: "):
			cur.Type = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.Data += strings.TrimPrefix(line, "data: ")
		default:
			t.Fatalf("unexpected SSE line %q", line)
		}
	}
	return out
}

// --- Plan -------------------------------------------------------------------

func TestPlanPage(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	p := runFixture(t, s, api, true, false)

	cfg, err := PlaceholderConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := authdiff.PlanContext(context.Background(), authdiff.ScanOptions{Config: cfg, BaseDir: s.store.Dir(p.Name)})
	if err != nil {
		t.Fatal(err)
	}
	destructive := 0
	rulesSeen := map[string]bool{}
	for _, pr := range plan {
		if pr.Destructive {
			destructive++
		}
		rulesSeen[pr.RuleID] = true
	}
	if destructive == 0 || len(plan) == 0 {
		t.Fatalf("fixture plan: %d requests, %d destructive", len(plan), destructive)
	}

	w := do(s, req(s, http.MethodGet, "/p/"+p.Name+"/plan", nil, true))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if n := strings.Count(body, `<tr class="destructive">`); n != destructive {
		t.Errorf("destructive rows = %d, want %d", n, destructive)
	}
	if !strings.Contains(body, fmt.Sprintf(`data-total="%d"`, len(plan))) {
		t.Errorf("total %d not on page", len(plan))
	}
	if !strings.Contains(body, fmt.Sprintf(`data-destructive="%d"`, destructive)) {
		t.Errorf("destructive total %d not on page", destructive)
	}
	for id := range rulesSeen {
		if !strings.Contains(body, `<h2 id="rule-`+id+`"`) {
			t.Errorf("rule group %s missing", id)
		}
	}
	if !strings.Contains(body, `action="/p/`+p.Name+`/scan"`) || !strings.Contains(body, s.csrf) {
		t.Error("scan form with CSRF token missing")
	}
	if !strings.Contains(body, `data-mode="destructive"`) {
		t.Error("destructive-mode warning missing")
	}
	// In safe mode the same destructive requests are blocked, not sent.
	p.Safety.AllowDestructive = false
	if err := s.store.Save(p); err != nil {
		t.Fatal(err)
	}
	safe := do(s, req(s, http.MethodGet, "/p/"+p.Name+"/plan", nil, true)).Body.String()
	if !strings.Contains(safe, `data-mode="safe"`) || strings.Contains(safe, `data-mode="destructive"`) {
		t.Error("safe mode plan does not say destructive requests are blocked")
	}
	// Missing credentials do not block the plan but are pointed out.
	if !strings.Contains(body, `href="/p/`+p.Name+`/profiles"`) {
		t.Error("missing-credentials notice not shown")
	}
}

func TestPlanPageUnknownProject(t *testing.T) {
	s := runServer(t, Options{})
	if w := do(s, req(s, http.MethodGet, "/p/nope/plan", nil, true)); w.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", w.Code)
	}
}

func TestPlanPageShowsConfigError(t *testing.T) {
	s := runServer(t, Options{})
	p := &Project{Name: "half", Step: "target"}
	if err := s.store.Save(p); err != nil {
		t.Fatal(err)
	}
	w := do(s, req(s, http.MethodGet, "/p/half/plan", nil, true))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), `class="err"`) || strings.Contains(w.Body.String(), `action="/p/half/scan"`) {
		t.Error("want an error and no scan button")
	}
	if !strings.Contains(w.Body.String(), `href="/p/half/target"`) {
		t.Error("no link to the target step")
	}
}

// A project the wizard let through without the scope acknowledgement
// fails config validation: plan and scan answer 422 with a link to the
// target step and never start a scan.
func TestPlanWithoutAckShowsError(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	p := runFixture(t, s, api, false, true)
	p.Acknowledged = false
	if err := s.store.Save(p); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*http.Request{
		req(s, http.MethodGet, "/p/"+p.Name+"/plan", nil, true),
		postForm(s, "/p/"+p.Name+"/scan", nil),
	} {
		w := do(s, r)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s %s: status %d, want 422", r.Method, r.URL.Path, w.Code)
			continue
		}
		body := w.Body.String()
		if !strings.Contains(body, `href="/p/`+p.Name+`/target"`) || !strings.Contains(body, `class="err"`) {
			t.Errorf("%s %s: no error with a link to the target step", r.Method, r.URL.Path)
		}
		if strings.Contains(body, `action="/p/`+p.Name+`/scan"`) {
			t.Errorf("%s %s: scan button shown", r.Method, r.URL.Path)
		}
	}
	if s.runs.Active() != "" || api.hits.Load() != 0 {
		t.Errorf("a scan started: active %q, %d requests", s.runs.Active(), api.hits.Load())
	}
}

func TestEstimate(t *testing.T) {
	for _, tc := range []struct {
		n    int
		rate float64
		want time.Duration
	}{
		{0, 5, 0},
		{10, 5, 2 * time.Second},
		{11, 5, 3 * time.Second},
		{10, 0, 0},
	} {
		if got := estimate(tc.n, tc.rate); got != tc.want {
			t.Errorf("estimate(%d, %v) = %v, want %v", tc.n, tc.rate, got, tc.want)
		}
	}
}

// --- Starting a scan --------------------------------------------------------

func TestScanRedirectsWhenSecretsMissing(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	runFixture(t, s, api, false, false)
	w := do(s, postForm(s, "/p/"+runProject+"/scan", nil))
	wantRedirect(t, w, "/p/"+runProject+"/profiles?missing=1")
	if s.runs.Active() != "" || api.hits.Load() != 0 {
		t.Error("a scan started without credentials")
	}
}

func TestScanNeedsCSRF(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	runFixture(t, s, api, false, true)
	r := postForm(s, "/p/"+runProject+"/scan", nil)
	r.Header.Set("Origin", "http://evil.example")
	if w := do(s, r); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin scan: status %d, want 403", w.Code)
	}
}

func TestSecondScanConflict(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, true, 0)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)
	if s.runs.Active() != id {
		t.Fatalf("active run %q, want %q", s.runs.Active(), id)
	}
	w := do(s, postForm(s, "/p/"+runProject+"/scan", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("second scan: status %d, want 409", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/p/`+runProject+`/runs/`+id+`"`) {
		t.Error("409 page does not link the running scan")
	}
	if _, err := s.runs.Start(getProject(t, s, runProject), nil, s.store.Dir(runProject)); !errors.Is(err, ErrBusy) {
		t.Errorf("Start while busy: %v, want ErrBusy", err)
	}
	api.open()
	waitRun(t, s, id)
	if s.runs.Active() != "" {
		t.Error("run still active after it finished")
	}
}
