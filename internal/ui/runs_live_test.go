package ui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

func sseRequest(s *Server, id string) *http.Request {
	return req(s, http.MethodGet, "/api/runs/"+id+"/events", nil, true)
}

// waitHits waits until api received at least n requests.
func waitHits(t *testing.T, api *runAPI, n int64) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); api.hits.Load() < n; {
		if time.Now().After(deadline) {
			t.Fatalf("scan sent %d requests, want %d", api.hits.Load(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSSEStream(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)

	w := do(s, sseRequest(s, id)) // returns once the stream ended
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("status %d, content type %q", w.Code, w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("security headers missing on the stream")
	}
	evs := parseSSE(t, w.Body.String())
	if len(evs) < 3 {
		t.Fatalf("only %d events: %s", len(evs), w.Body.String())
	}
	counts := map[string]int{}
	for _, e := range evs {
		counts[e.Type]++
	}
	if counts["progress"] == 0 || counts["finding"] == 0 {
		t.Errorf("event counts %v, want progress and finding events", counts)
	}
	last := evs[len(evs)-1]
	if last.Type != "done" || counts["done"] != 1 || counts["error"] != 0 {
		t.Fatalf("last event %q, counts %v", last.Type, counts)
	}
	var done RunDone
	if err := json.Unmarshal([]byte(last.Data), &done); err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, id)
	res := readResult(t, s, id)
	if done.Status != "done" || done.Sent != res.Stats.Requests || done.Sent == 0 {
		t.Errorf("done %+v, results.json requests %d", done, res.Stats.Requests)
	}
	if done.Findings != len(res.Active()) || done.Findings == 0 {
		t.Errorf("done findings %d, results.json %d", done.Findings, len(res.Active()))
	}
	if done.Results != "/p/"+runProject+"/runs/"+id+"/results" {
		t.Errorf("results link %q", done.Results)
	}
	for _, f := range []string{"results.json", "results.sarif", "report.html"} {
		if _, err := os.Stat(filepath.Join(s.store.RunsDir(runProject), id, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	var pr RunProgress
	for _, e := range evs {
		if e.Type != "progress" {
			continue
		}
		if err := json.Unmarshal([]byte(e.Data), &pr); err != nil {
			t.Fatal(err)
		}
		if pr.Percent > 99 {
			t.Errorf("progress percent %d before done", pr.Percent)
		}
	}

	// A late subscriber gets the final state and the end at once.
	w = do(s, sseRequest(s, id))
	evs = parseSSE(t, w.Body.String())
	if len(evs) < 2 || evs[0].Type != "progress" || evs[len(evs)-1].Type != "done" {
		t.Fatalf("late stream: %v", evs)
	}
	if err := json.Unmarshal([]byte(evs[0].Data), &pr); err != nil {
		t.Fatal(err)
	}
	if pr.Percent != 100 || pr.Sent != res.Stats.Requests {
		t.Errorf("late snapshot %+v", pr)
	}
}

func TestSSEUnknownRun(t *testing.T) {
	s := runServer(t, Options{})
	for _, p := range []string{"/api/runs/20260101-000000/events", "/api/runs/abc/events"} {
		if w := do(s, req(s, http.MethodGet, p, nil, true)); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, w.Code)
		}
	}
	if w := do(s, req(s, http.MethodGet, "/api/runs/20260101-000000/events", nil, false)); w.Code != http.StatusUnauthorized {
		t.Errorf("without session: status %d, want 401", w.Code)
	}
}

func TestSSEHeartbeat(t *testing.T) {
	old := sseHeartbeat
	sseHeartbeat = 20 * time.Millisecond
	t.Cleanup(func() { sseHeartbeat = old })
	s := runServer(t, Options{})
	api := newRunAPI(t, true, 0)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)
	go func() {
		time.Sleep(150 * time.Millisecond)
		api.open()
	}()
	w := do(s, sseRequest(s, id))
	if !strings.Contains(w.Body.String(), ": ping\n\n") {
		t.Errorf("no heartbeat comment in %q", w.Body.String())
	}
}

func TestRunContinuesWithoutClient(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, true, 1)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	r := sseRequest(s, id).WithContext(ctx)
	ended := make(chan struct{})
	go func() {
		do(s, r)
		close(ended)
	}()
	waitHits(t, api, 2)
	cancel() // the browser tab is closed
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("SSE handler did not return after the client left")
	}
	if s.runs.Active() != id {
		t.Fatal("run stopped with its client")
	}
	api.open()
	waitRun(t, s, id)
	if res := readResult(t, s, id); res.Stats.Requests < 2 {
		t.Errorf("results.json has %d requests", res.Stats.Requests)
	}
}

func TestStopWritesPartial(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, true, 2)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)
	waitHits(t, api, 3)
	ch, unsub := s.runs.Subscribe(id)
	defer unsub()

	w := do(s, postForm(s, "/api/runs/"+id+"/stop", nil))
	wantRedirect(t, w, "/p/"+runProject+"/runs/"+id)
	select {
	case <-s.runs.doneCh(id):
	default:
		t.Fatal("Stop returned before the run ended")
	}
	res := readResult(t, s, id)
	if res.Stats.Requests < 2 {
		t.Errorf("partial result has %d requests", res.Stats.Requests)
	}
	var last Event
	for ev := range ch {
		last = ev
	}
	if d, ok := last.Data.(RunDone); last.Type != "done" || !ok || d.Status != "stopped" {
		t.Errorf("last event %+v, want done/stopped", last)
	}
	// Stopping a run that already finished goes to its page.
	wantRedirect(t, do(s, postForm(s, "/api/runs/"+id+"/stop", nil)), "/p/"+runProject+"/runs/"+id)
	// The finished run's page goes to its results.
	wantRedirect(t, do(s, req(s, http.MethodGet, "/p/"+runProject+"/runs/"+id, nil, true)),
		"/p/"+runProject+"/runs/"+id+"/results")
}

func TestStopFromScriptAnswersJSON(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, true, 0)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)
	r := req(s, http.MethodPost, "/api/runs/"+id+"/stop", nil, true)
	r.Header.Set("Origin", "http://127.0.0.1:7465")
	r.Header.Set("X-CSRF-Token", s.csrf)
	w := do(s, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"/p/`+runProject+`/runs/`+id+`/results"`) {
		t.Errorf("status %d body %s", w.Code, w.Body.String())
	}
	if w := do(s, postForm(s, "/api/runs/x/stop", nil)); w.Code != http.StatusNotFound {
		t.Errorf("malformed ID: status %d, want 404", w.Code)
	}
}

func TestServeCancelStopsRun(t *testing.T) {
	s := runServer(t, Options{Port: freePort(t)})
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	api := newRunAPI(t, true, 1)
	p := runFixture(t, s, api, false, true)
	cfg, err := BuildConfig(p, s.secrets, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx) }()
	id, err := s.runs.Start(p, cfg, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	waitHits(t, api, 2)
	cancel() // Ctrl-C
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
	if res := readResult(t, s, id); res.Stats.Requests < 1 {
		t.Errorf("partial result has %d requests", res.Stats.Requests)
	}
	if _, err := s.runs.Start(p, cfg, s.store.Dir(p.Name)); err == nil {
		t.Error("a scan started after shutdown")
	}
}

func TestRunFilesNoSecrets(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)
	w := do(s, sseRequest(s, id))
	waitRun(t, s, id)
	if _, err := os.Stat(filepath.Join(s.store.RunsDir(runProject), id, "results.json")); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, s.opts.ProjectsDir, runAliceToken, runBobToken)
	for _, tok := range []string{runAliceToken, runBobToken} {
		if strings.Contains(w.Body.String(), tok) {
			t.Errorf("event stream contains %q", tok)
		}
	}
}

func TestRunPage(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, true, 0)
	runFixture(t, s, api, false, true)
	id := startScan(t, s)
	w := do(s, req(s, http.MethodGet, "/p/"+runProject+"/runs/"+id, nil, true))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`data-events="/api/runs/` + id + `/events"`,
		`<meta http-equiv="refresh" content="3">`,
		`action="/api/runs/` + id + `/stop"`,
		`<progress`,
		s.csrf,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("run page lacks %q", want)
		}
	}
	for _, p := range []string{"/p/other/runs/" + id, "/p/" + runProject + "/runs/20200101-000000", "/p/" + runProject + "/runs/x"} {
		if w := do(s, req(s, http.MethodGet, p, nil, true)); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, w.Code)
		}
	}
	api.open()
	waitRun(t, s, id)
}

// A finished run from an earlier session (on disk only) goes to its results.
func TestRunPageFromDisk(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	runFixture(t, s, api, false, true)
	dir := filepath.Join(s.store.RunsDir(runProject), "20250101-120000")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "results.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantRedirect(t, do(s, req(s, http.MethodGet, "/p/"+runProject+"/runs/20250101-120000", nil, true)),
		"/p/"+runProject+"/runs/20250101-120000/results")
}

func TestRunIDSuffix(t *testing.T) {
	m := newRunManager("test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	fixed := time.Date(2026, 11, 23, 14, 2, 11, 0, time.Local)
	m.now = func() time.Time { return fixed }
	root := t.TempDir()
	var ids []string
	for i := 0; i < 3; i++ {
		id, _, err := m.newRunDir(root)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	want := []string{"20261123-140211", "20261123-140211-2", "20261123-140211-3"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("ids %v, want %v", ids, want)
	}
	for _, id := range ids {
		if !validRunID(id) {
			t.Errorf("%s not valid", id)
		}
	}
	for _, bad := range []string{"", "2026112-140211", "20261123-140211-", "../20261123-140211", "20261123-140211-2a"} {
		if validRunID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPercent(t *testing.T) {
	for _, tc := range []struct{ sent, planned, want int }{
		{0, 10, 0}, {5, 10, 50}, {10, 10, 99}, {15, 10, 99}, {3, 0, 0},
	} {
		if got := percent(tc.sent, tc.planned); got != tc.want {
			t.Errorf("percent(%d, %d) = %d, want %d", tc.sent, tc.planned, got, tc.want)
		}
	}
}

// The hook never blocks on a full buffer; a scan error without a result
// ends with an error event and leaves no run dir; a panicking scan is an
// error event, not a crash.
func TestRunErrorAndHook(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	p := runFixture(t, s, api, false, true)
	cfg, err := BuildConfig(p, s.secrets, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	s.runs.scan = func(_ context.Context, o authdiff.ScanOptions) (*authdiff.Result, error) {
		for i := 0; i < hookBuffer*2; i++ {
			o.OnProgress(authdiff.Progress{Sent: i, Planned: 10})
		}
		return nil, errors.New("spec unreachable")
	}
	id, err := s.runs.Start(p, cfg, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, id)
	ch, _ := s.runs.Subscribe(id)
	var last Event
	for ev := range ch {
		last = ev
	}
	if e, ok := last.Data.(RunError); last.Type != "error" || !ok || e.Message != "spec unreachable" {
		t.Errorf("last event %+v", last)
	}
	if _, err := os.Stat(filepath.Join(s.store.RunsDir(p.Name), id)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("run dir left behind: %v", err)
	}

	s.runs.scan = func(context.Context, authdiff.ScanOptions) (*authdiff.Result, error) { panic("boom") }
	id, err = s.runs.Start(p, cfg, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, id)
	if v, ok := s.runs.view(id); !ok || !v.Finished {
		t.Errorf("view %+v", v)
	}
}

// A scan that fails without a result (spec unreachable) keeps its run page:
// 200 with the reason, no stop form and no refresh, never a redirect to
// results that cannot exist.
func TestRunPageShowsScanError(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	p := runFixture(t, s, api, false, true)
	cfg, err := BuildConfig(p, s.secrets, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	s.runs.scan = func(context.Context, authdiff.ScanOptions) (*authdiff.Result, error) {
		return nil, errors.New("load spec: connection refused")
	}
	id, err := s.runs.Start(p, cfg, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, id)
	w := do(s, req(s, http.MethodGet, "/p/"+p.Name+"/runs/"+id, nil, true))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d (Location %q), want 200", w.Code, w.Header().Get("Location"))
	}
	body := w.Body.String()
	if !strings.Contains(body, "load spec: connection refused") || !strings.Contains(body, "The scan could not run") {
		t.Error("run page lacks the error")
	}
	for _, bad := range []string{`http-equiv="refresh"`, `action="/api/runs/` + id + `/stop"`, `data-events=`} {
		if strings.Contains(body, bad) {
			t.Errorf("failed run page contains %q", bad)
		}
	}
	// Stop on it goes to the same page.
	wantRedirect(t, do(s, postForm(s, "/api/runs/"+id+"/stop", nil)), "/p/"+p.Name+"/runs/"+id)
}

// When writing the reports fails, no partial results.json is left for the
// run page's disk fallback to redirect to.
func TestRunWriteFailureLeavesNoResults(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	p := runFixture(t, s, api, false, true)
	cfg, err := BuildConfig(p, s.secrets, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	s.runs.write = func(dir string, _ []string, _ *finding.Result, _ io.Writer, _ bool) ([]string, error) {
		if err := os.WriteFile(filepath.Join(dir, "results.json"), []byte("{"), 0o600); err != nil {
			return nil, err
		}
		return nil, errors.New("disk full")
	}
	id, err := s.runs.Start(p, cfg, s.store.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}
	waitRun(t, s, id)
	if _, err := os.Stat(filepath.Join(s.store.RunsDir(p.Name), id, "results.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("results.json left behind: %v", err)
	}
	w := do(s, req(s, http.MethodGet, "/p/"+p.Name+"/runs/"+id, nil, true))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "disk full") {
		t.Errorf("status %d, want 200 with the write error", w.Code)
	}
}
