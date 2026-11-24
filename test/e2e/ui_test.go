//go:build e2e

package e2e

// TestUIDemoMatchesOracle drives `authdiff ui` over HTTP like a browser
// would: it logs in with the session URL, creates the demo project, turns
// destructive mode on in the settings (typing the confirmation), starts the
// scan, follows the run's event stream until it is done and checks the
// downloaded results.json against the same oracle as TestVulnLab.
//
// The destructive scan mutates the lab, so this test needs a fresh lab of
// its own; never run it in the same `go test` invocation as TestVulnLab:
//
//	docker compose up -d --build --force-recreate vuln-lab
//	go test -tags e2e -count=1 -run TestUIDemoMatchesOracle ./test/e2e/...

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/report"
	"github.com/ardayesilcayir/authdiff/internal/ui"
)

// uiClient is a cookie-keeping HTTP client for the UI that does not follow
// redirects, so each step can check where the server sends it.
type uiClient struct {
	t      *testing.T
	ctx    context.Context
	origin string // http://127.0.0.1:<port>
	c      *http.Client
}

func newUIClient(ctx context.Context, t *testing.T, sessionURL string) *uiClient {
	t.Helper()
	u, err := url.Parse(sessionURL)
	if err != nil {
		t.Fatalf("session URL %q: %v", sessionURL, err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &uiClient{
		t: t, ctx: ctx, origin: u.Scheme + "://" + u.Host,
		c: &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (u *uiClient) do(req *http.Request) (*http.Response, []byte) {
	u.t.Helper()
	resp, err := u.c.Do(req)
	if err != nil {
		u.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		u.t.Fatalf("%s %s: read body: %v", req.Method, req.URL.Path, err)
	}
	return resp, body
}

// get fetches path (or a full URL) and requires status want.
func (u *uiClient) get(path string, want int) (*http.Response, []byte) {
	u.t.Helper()
	target := path
	if strings.HasPrefix(path, "/") {
		target = u.origin + path
	}
	req, err := http.NewRequestWithContext(u.ctx, http.MethodGet, target, nil)
	if err != nil {
		u.t.Fatal(err)
	}
	resp, body := u.do(req)
	if resp.StatusCode != want {
		u.t.Fatalf("GET %s: status %d, want %d\n%s", req.URL.Path, resp.StatusCode, want, snippet(body))
	}
	return resp, body
}

// post submits form to path as a same-origin browser form and returns the
// redirect target; anything but 303 fails the test.
func (u *uiClient) post(path string, form url.Values) string {
	u.t.Helper()
	req, err := http.NewRequestWithContext(u.ctx, http.MethodPost, u.origin+path, strings.NewReader(form.Encode()))
	if err != nil {
		u.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", u.origin)
	resp, body := u.do(req)
	if resp.StatusCode != http.StatusSeeOther {
		u.t.Fatalf("POST %s: status %d, want 303\n%s", path, resp.StatusCode, snippet(body))
	}
	return resp.Header.Get("Location")
}

func snippet(b []byte) string {
	const limit = 2000
	if len(b) > limit {
		return string(b[:limit]) + "..."
	}
	return string(b)
}

var (
	formRe     = regexp.MustCompile(`(?s)<form\b([^>]*)>(.*?)</form>`)
	inputRe    = regexp.MustCompile(`<input\b([^>]*)>`)
	textareaRe = regexp.MustCompile(`(?s)<textarea\b([^>]*)>(.*?)</textarea>`)
	attrRe     = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:="([^"]*)")?`)
)

func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		out[strings.ToLower(m[1])] = html.UnescapeString(m[2])
	}
	return out
}

// formValues returns what a browser would submit for the form whose action
// is action (without pressing a named button): named text, number, hidden
// and url inputs, checked checkboxes and textareas. The UI's templates use
// no select or radio inputs in the forms this test submits.
func formValues(t *testing.T, page []byte, action string) url.Values {
	t.Helper()
	for _, m := range formRe.FindAllStringSubmatch(string(page), -1) {
		if attrs(m[1])["action"] != action {
			continue
		}
		v := url.Values{}
		for _, in := range inputRe.FindAllStringSubmatch(m[2], -1) {
			a := attrs(in[1])
			name := a["name"]
			if name == "" {
				continue
			}
			switch a["type"] {
			case "checkbox", "radio":
				if _, checked := a["checked"]; checked {
					val := a["value"]
					if val == "" {
						val = "on"
					}
					v.Add(name, val)
				}
			case "submit", "button", "file":
			default:
				v.Add(name, a["value"])
			}
		}
		for _, ta := range textareaRe.FindAllStringSubmatch(m[2], -1) {
			if name := attrs(ta[1])["name"]; name != "" {
				// Browsers drop one leading newline of a textarea.
				v.Add(name, strings.TrimPrefix(html.UnescapeString(ta[2]), "\n"))
			}
		}
		if v.Get("csrf") == "" {
			t.Fatalf("form %s has no csrf field", action)
		}
		return v
	}
	t.Fatalf("no form with action %s on the page\n%s", action, snippet(page))
	return nil
}

// runDone is the data of the run's final "done" event.
type runDone struct {
	Status   string `json:"status"`
	Sent     int    `json:"sent"`
	Blocked  int    `json:"blocked"`
	Errors   int    `json:"errors"`
	Findings int    `json:"findings"`
	Results  string `json:"results"`
	Message  string `json:"message"`
}

// waitDone reads the run's event stream until its last event and returns
// the done event's data; an "error" event or a stream that ends without
// one fails the test.
func (u *uiClient) waitDone(id string) runDone {
	u.t.Helper()
	req, err := http.NewRequestWithContext(u.ctx, http.MethodGet, u.origin+"/api/runs/"+id+"/events", nil)
	if err != nil {
		u.t.Fatal(err)
	}
	resp, err := u.c.Do(req)
	if err != nil {
		u.t.Fatalf("event stream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		u.t.Fatalf("event stream: status %d, content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var event string
	progress := 0
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data := strings.TrimPrefix(line, "data: ")
			switch event {
			case "progress":
				progress++
			case "error":
				u.t.Fatalf("run %s failed: %s", id, data)
			case "done":
				var d runDone
				if err := json.Unmarshal([]byte(data), &d); err != nil {
					u.t.Fatalf("done event %q: %v", data, err)
				}
				u.t.Logf("run %s: %d progress events, done: %s", id, progress, data)
				return d
			}
		}
	}
	err = sc.Err()
	if errors.Is(u.ctx.Err(), context.DeadlineExceeded) {
		err = u.ctx.Err()
	}
	u.t.Fatalf("event stream of run %s ended without a done event: %v", id, err)
	return runDone{}
}

func TestUIDemoMatchesOracle(t *testing.T) {
	base := labURL()
	orc := loadOracle(t)
	waitForLab(t, base)

	srv, err := ui.New(ui.Options{
		Port:        17465,
		ProjectsDir: t.TempDir(),
		Version:     "e2e",
		LabURL:      base,
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	sessionURL, err := srv.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	srvCtx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(srvCtx) }()
	defer func() {
		stop()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	c := newUIClient(ctx, t, sessionURL)

	// Log in: the key sets the session cookie and redirects to "/".
	resp, _ := c.get(sessionURL, http.StatusSeeOther)
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("login redirect to %q, want /", loc)
	}
	_, home := c.get("/", http.StatusOK)

	// Demo project.
	loc := c.post("/demo", formValues(t, home, "/demo"))
	if want := "/p/" + ui.DemoName + "/plan"; loc != want {
		t.Fatalf("demo redirect to %q, want %q", loc, want)
	}

	// Destructive mode needs the typed confirmation.
	settingsPath := "/p/" + ui.DemoName + "/settings"
	_, page := c.get(settingsPath, http.StatusOK)
	form := formValues(t, page, settingsPath)
	form.Set("destructive", "on")
	form.Set("confirm", "anladım")
	loc = c.post(settingsPath, form)
	planPath := "/p/" + ui.DemoName + "/plan"
	if loc != planPath {
		t.Fatalf("settings redirect to %q, want %q", loc, planPath)
	}
	_, page = c.get(settingsPath, http.StatusOK)
	if !strings.Contains(string(page), "data-confirmed") {
		t.Fatal("destructive mode is not on after the confirmed settings")
	}

	// Start the scan from the plan page.
	_, page = c.get(planPath, http.StatusOK)
	if !strings.Contains(string(page), `data-mode="destructive"`) {
		t.Fatal("plan page does not announce the destructive mode")
	}
	scanPath := "/p/" + ui.DemoName + "/scan"
	loc = c.post(scanPath, formValues(t, page, scanPath))
	runPrefix := "/p/" + ui.DemoName + "/runs/"
	if !strings.HasPrefix(loc, runPrefix) {
		t.Fatalf("scan redirect to %q, want %s<id>", loc, runPrefix)
	}
	id := strings.TrimPrefix(loc, runPrefix)

	done := c.waitDone(id)
	if done.Status != "done" {
		t.Fatalf("run ended with status %q: %s", done.Status, done.Message)
	}
	resultsPath := runPrefix + id + "/results"
	if done.Results != resultsPath {
		t.Errorf("done event points at %q, want %q", done.Results, resultsPath)
	}
	t.Logf("scan: %d findings, %d requests, %d blocked, %d errors",
		done.Findings, done.Sent, done.Blocked, done.Errors)

	// The results page renders, and results.json is what the CLI writes.
	c.get(resultsPath, http.StatusOK)
	_, raw := c.get(runPrefix+id+"/download/results.json", http.StatusOK)
	res, err := report.ReadJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("results.json: %v", err)
	}
	checkOracle(t, orc, res)
}
