package ui

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/report"
)

const (
	resProject = "shop"
	resRun     = "20261124-101500"
	idNoAuth   = "aaaaaaaaaaaa"
	idBola     = "bbbbbbbbbbbb"
	idBolaSupp = "cccccccccccc"
	idLow      = "dddddddddddd"
)

// resultFixture is a scan result with one finding per interesting case:
// a critical one whose evidence carries a script tag and a body over the
// display cap, two BOLA findings (one suppressed at scan time) and a low one.
func resultFixture() *finding.Result {
	t0 := time.Date(2026, 11, 24, 10, 15, 0, 0, time.UTC)
	big := strings.Repeat("x", 20<<10) + "TAIL-MARKER"
	return &finding.Result{
		Tool:       finding.Tool{Name: "authdiff", Version: "test"},
		Target:     "http://127.0.0.1:8000",
		SpecPath:   "spec.yaml",
		StartedAt:  t0,
		FinishedAt: t0.Add(3 * time.Second),
		Profiles:   []string{"alice", "bob", "anonymous"},
		Stats:      finding.Stats{Endpoints: 2, Requests: 41, Blocked: 3, Errors: 2},
		Notes:      []string{"TLS certificate verification was disabled"},
		Findings: []finding.Finding{
			{ID: idNoAuth, RuleID: "AD-NOAUTH-001", Title: "Endpoint reachable without authentication", Description: "GET /orders/{orderId} answered anonymous.", Severity: finding.Critical, Confidence: finding.ConfHigh, Method: "GET", Path: "/orders/{orderId}", Victim: "alice", Attacker: "anonymous", Similarity: 0.97, Remediation: "Require authentication.", OWASP: "API2:2023", CWE: "CWE-306",
				Evidence: []finding.Exchange{
					{Step: "attacker", Profile: "anonymous", Method: "GET", URL: "http://127.0.0.1:8000/orders/101", Status: 200, RequestHeaders: map[string]string{"Accept": "application/json"}, ResponseHeaders: map[string]string{"Content-Type": "text/html"}, ResponseBody: `<script>alert(1)</script>`},
					{Step: "victim", Profile: "alice", Method: "GET", URL: "http://127.0.0.1:8000/orders/101", Status: 200, ResponseBody: big, Truncated: true},
				}},
			{ID: idBola, RuleID: "AD-BOLA-001", Title: "Cross-user object read", Severity: finding.High, Confidence: finding.ConfMedium, Method: "GET", Path: "/orders/{orderId}", Victim: "alice", Attacker: "bob", Similarity: 0.91},
			{ID: idBolaSupp, RuleID: "AD-BOLA-001", Title: "Cross-user object read", Severity: finding.High, Confidence: finding.ConfLow, Method: "GET", Path: "/users/{id}", Victim: "bob", Attacker: "alice", Similarity: 0.88, Suppressed: true},
			{ID: idLow, RuleID: "AD-VERB-001", Title: "Verb tampering", Severity: finding.Low, Confidence: finding.ConfLow, Method: "PUT", Path: "/users/{id}", Attacker: "bob"},
		},
		Matrix: []finding.MatrixCell{
			{Endpoint: "GET /orders/{orderId}", Profile: "alice", Status: 200, Outcome: finding.Allowed},
			{Endpoint: "GET /orders/{orderId}", Profile: "bob", Status: 200, Outcome: finding.Unexpected},
			{Endpoint: "GET /orders/{orderId}", Profile: "anonymous", Status: 401, Outcome: finding.Denied},
		},
	}
}

// resultsServer saves project shop with one run on disk (written the way a
// scan writes it) and returns the server.
func resultsServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t, Options{})
	p := sampleProject()
	p.Name = resProject
	if err := s.store.Save(p); err != nil {
		t.Fatal(err)
	}
	writeRun(t, s, resProject, resRun, resultFixture())
	return s
}

func writeRun(t *testing.T, s *Server, project, id string, r *finding.Result) {
	t.Helper()
	if _, err := report.Write(filepath.Join(s.store.RunsDir(project), id), runFormats, r, nil, false); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, s *Server, target string) (int, string) {
	t.Helper()
	w := do(s, req(s, http.MethodGet, target, nil, true))
	return w.Code, w.Body.String()
}

const resultsURL = "/p/" + resProject + "/runs/" + resRun + "/results"

func findingURL(id string) string {
	return "/p/" + resProject + "/runs/" + resRun + "/findings/" + id
}

// --- Results page -------------------------------------------------------------

func TestResultsPage(t *testing.T) {
	s := resultsServer(t)
	code, body := get(t, s, resultsURL)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	res := resultFixture()
	counts := map[finding.Severity]int{}
	for _, f := range res.Active() {
		counts[f.Severity]++
	}
	for _, sev := range []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info} {
		want := fmt.Sprintf(`id="n-%s">%d<`, sev, counts[sev])
		if !strings.Contains(body, want) {
			t.Errorf("severity count %s: want %s", sev, want)
		}
	}
	for k, v := range map[string]int{"requests": res.Stats.Requests, "blocked": res.Stats.Blocked, "errors": res.Stats.Errors} {
		if want := fmt.Sprintf(`id="n-%s">%d<`, k, v); !strings.Contains(body, want) {
			t.Errorf("stat %s: want %s", k, want)
		}
	}
	if !strings.Contains(body, `id="n-duration">3s<`) {
		t.Error("duration card missing")
	}
	if !strings.Contains(body, "TLS certificate verification was disabled") {
		t.Error("notes missing")
	}
	hm, err := report.Heatmap(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, string(hm)) {
		t.Error("results page does not contain the report's heatmap markup")
	}
	for _, id := range []string{idNoAuth, idBola, idLow} {
		if !strings.Contains(body, `href="`+findingURL(id)+`"`) {
			t.Errorf("active finding %s not linked", id)
		}
	}
	// The suppressed finding is in its own section only.
	active, supp := splitSuppressed(t, body)
	if strings.Contains(active, idBolaSupp) {
		t.Error("suppressed finding listed among active ones")
	}
	if !strings.Contains(supp, idBolaSupp) {
		t.Error("suppressed finding missing from the suppressed section")
	}
	for _, f := range []string{"results.json", "results.sarif", "report.html"} {
		if !strings.Contains(body, `href="/p/`+resProject+`/runs/`+resRun+`/download/`+f+`"`) {
			t.Errorf("download link %s missing", f)
		}
	}
	if !strings.Contains(body, `href="/p/`+resProject+`/export.zip"`) {
		t.Error("export link missing")
	}
}

// splitSuppressed returns the page before and after the suppressed section.
func splitSuppressed(t *testing.T, body string) (string, string) {
	t.Helper()
	i := strings.Index(body, `id="suppressed"`)
	if i < 0 {
		t.Fatal("no suppressed section")
	}
	return body[:i], body[i:]
}

func TestResultsFilter(t *testing.T) {
	s := resultsServer(t)
	listed := func(body string) []string {
		active, _ := splitSuppressed(t, body)
		var out []string
		for _, id := range []string{idNoAuth, idBola, idLow} {
			if strings.Contains(active, `href="`+findingURL(id)+`"`) {
				out = append(out, id)
			}
		}
		return out
	}
	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{idNoAuth, idBola, idLow}},
		{"?sev=high", []string{idBola}},
		{"?sev=critical", []string{idNoAuth}},
		{"?rule=AD-BOLA-001", []string{idBola}},
		{"?sev=low&rule=AD-VERB-001", []string{idLow}},
		{"?sev=high&rule=AD-VERB-001", nil},
		{"?sev=medium", nil},
		{"?sev=bogus", []string{idNoAuth, idBola, idLow}},
	}
	for _, c := range cases {
		code, body := get(t, s, resultsURL+c.query)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d", c.query, code)
		}
		if got := listed(body); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%q: listed %v, want %v", c.query, got, c.want)
		}
	}
	// The chosen filter is kept in the form.
	_, body := get(t, s, resultsURL+"?sev=high&rule=AD-BOLA-001")
	if !regexp.MustCompile(`<option value="high" selected>`).MatchString(body) ||
		!regexp.MustCompile(`<option value="AD-BOLA-001" selected>`).MatchString(body) {
		t.Error("filter selection not kept")
	}
}

func TestResultsNotFound(t *testing.T) {
	s := resultsServer(t)
	for _, u := range []string{
		"/p/" + resProject + "/runs/20261124-999999/results", // no such run
		"/p/" + resProject + "/runs/2026-11-24/results",      // bad id
		"/p/nope/runs/" + resRun + "/results",                // no such project
		"/p/" + resProject + "/runs/" + resRun + "/findings/zzzzzzzzzzzz",
		"/p/" + resProject + "/runs/" + resRun + "/findings/0123456789ab", // valid but not in run
	} {
		if code, _ := get(t, s, u); code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", u, code)
		}
	}
}

func TestResultsCorruptRun(t *testing.T) {
	s := resultsServer(t)
	dir := filepath.Join(s.store.RunsDir(resProject), "20261124-101501")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "results.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, s, "/p/"+resProject+"/runs/20261124-101501/results"); code != http.StatusInternalServerError {
		t.Errorf("corrupt results.json: status %d, want 500", code)
	}
}

// --- Finding detail -------------------------------------------------------------

func TestFindingEvidenceEscaped(t *testing.T) {
	s := resultsServer(t)
	code, body := get(t, s, findingURL(idNoAuth))
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("response body rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped response body missing")
	}
	for _, want := range []string{
		"Endpoint reachable without authentication",
		"GET /orders/{orderId} answered anonymous.",
		"Require authentication.",
		`href="https://github.com/ardayesilcayir/authdiff/blob/main/docs/rules/AD-NOAUTH-001.md"`,
		"97%",
		"Content-Type: text/html",
		"Accept: application/json",
		`name="reason"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page lacks %q", want)
		}
	}
	// The 20 KiB body is cut at the display cap.
	if strings.Contains(body, "TAIL-MARKER") {
		t.Error("body over the display cap shown in full")
	}
	if strings.Count(body, "x") > 17<<10 {
		t.Error("displayed body larger than the cap")
	}
}

func TestFindingRuleLinkValidated(t *testing.T) {
	if got := ruleDocURL("AD-BOLA-001"); got != "https://github.com/ardayesilcayir/authdiff/blob/main/docs/rules/AD-BOLA-001.md" {
		t.Errorf("ruleDocURL = %q", got)
	}
	for _, bad := range []string{"", "ad-bola-001", "../../x", "AD-BOLA-001/../../y", "AD"} {
		if got := ruleDocURL(bad); got != "" {
			t.Errorf("ruleDocURL(%q) = %q, want none", bad, got)
		}
	}
}

func TestCapBody(t *testing.T) {
	s, cut := capBody("héllo", 10)
	if s != "héllo" || cut {
		t.Errorf("short body changed: %q %v", s, cut)
	}
	s, cut = capBody(strings.Repeat("é", 10), 5) // 2-byte runes: never split one
	if !cut || s != "éé" {
		t.Errorf("capBody = %q %v", s, cut)
	}
}

// --- Triage ---------------------------------------------------------------------

func ignoreURL(id string) string { return findingURL(id) + "/ignore" }

func TestIgnoreRequiresReason(t *testing.T) {
	s := resultsServer(t)
	ign := filepath.Join(s.store.Dir(resProject), ignoreFile)
	for _, reason := range []string{"", "   \n "} {
		w := do(s, postForm(s, ignoreURL(idBola), url.Values{"reason": {reason}}))
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("reason %q: status %d, want 422", reason, w.Code)
		}
		if !strings.Contains(w.Body.String(), `aria-invalid="true"`) {
			t.Error("missing reason not marked on the form")
		}
		if _, err := os.Stat(ign); !os.IsNotExist(err) {
			t.Fatal("ignore file written without a reason")
		}
	}
	// No CSRF token: blocked by the security layer.
	r := req(s, http.MethodPost, ignoreURL(idBola), strings.NewReader("reason=x"), true)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:7465")
	if w := do(s, r); w.Code != http.StatusForbidden {
		t.Errorf("without CSRF: status %d, want 403", w.Code)
	}
	// A finding that is not in the run.
	if w := do(s, postForm(s, ignoreURL("0123456789ab"), url.Values{"reason": {"x"}})); w.Code != http.StatusNotFound {
		t.Errorf("unknown finding: status %d, want 404", w.Code)
	}

	w := do(s, postForm(s, ignoreURL(idBola), url.Values{"reason": {"test account # shared\nby design"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("ignore: status %d: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, resultsURL) {
		t.Errorf("redirected to %q", loc)
	}
	b, err := os.ReadFile(ign) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != idBola+" # test account shared by design\n" {
		t.Errorf("ignore file = %q", b)
	}
	// The results page shows it suppressed at once, with the reason.
	_, body := get(t, s, resultsURL)
	active, supp := splitSuppressed(t, body)
	if strings.Contains(active, findingURL(idBola)) {
		t.Error("ignored finding still listed as active")
	}
	if !strings.Contains(supp, idBola) || !strings.Contains(supp, "test account shared by design") {
		t.Error("ignored finding or its reason missing from the suppressed section")
	}
	if !strings.Contains(body, `id="n-high">0<`) {
		t.Error("severity count not updated after ignoring")
	}
	// Its detail page says so and offers no second ignore form.
	_, detail := get(t, s, findingURL(idBola))
	if strings.Contains(detail, `name="reason"`) || !strings.Contains(detail, "test account shared by design") {
		t.Error("detail page of an ignored finding")
	}
}

func TestIgnorePersists(t *testing.T) {
	s := runServer(t, Options{})
	api := newRunAPI(t, false, 0)
	runFixture(t, s, api, false, true)
	first := startScan(t, s)
	waitRun(t, s, first)
	res := readResult(t, s, first)
	active := res.Active()
	if len(active) == 0 {
		t.Fatal("first scan found nothing")
	}
	id := active[0].ID
	u := "/p/" + runProject + "/runs/" + first + "/findings/" + id + "/ignore"
	if w := do(s, postForm(s, u, url.Values{"reason": {"accepted risk"}})); w.Code != http.StatusSeeOther {
		t.Fatalf("ignore: status %d: %s", w.Code, w.Body.String())
	}
	second := startScan(t, s)
	waitRun(t, s, second)
	for _, f := range readResult(t, s, second).Findings {
		if f.ID == id && !f.Suppressed {
			t.Fatalf("finding %s not suppressed in the next scan", id)
		}
	}
}

// --- Downloads and export -------------------------------------------------------

func TestDownloads(t *testing.T) {
	s := resultsServer(t)
	base := "/p/" + resProject + "/runs/" + resRun + "/download/"
	for file, ctype := range map[string]string{
		"results.json": "application/json", "results.sarif": "application/sarif+json", "report.html": "text/html",
	} {
		w := do(s, req(s, http.MethodGet, base+file, nil, true))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", file, w.Code)
		}
		if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, file) {
			t.Errorf("%s: Content-Disposition %q", file, cd)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, ctype) {
			t.Errorf("%s: Content-Type %q", file, ct)
		}
		disk, err := os.ReadFile(filepath.Join(s.store.RunsDir(resProject), resRun, file)) //nolint:gosec // G304: test temp dir
		if err != nil {
			t.Fatal(err)
		}
		if w.Body.String() != string(disk) {
			t.Errorf("%s: body differs from the file written at scan time", file)
		}
	}
}

func TestDownloadPathTraversal(t *testing.T) {
	s := resultsServer(t)
	if err := os.WriteFile(filepath.Join(s.store.RunsDir(resProject), "secret.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"/p/" + resProject + "/runs/" + resRun + "/download/project.json",
		"/p/" + resProject + "/runs/" + resRun + "/download/..%2F..%2Fproject.json",
		"/p/" + resProject + "/runs/" + resRun + "/download/..%5Csecret.txt",
		"/p/" + resProject + "/runs/..%2Fsecret.txt/download/results.json",
		"/p/" + resProject + "/runs/..%5C..%5Cshop/download/results.json",
		"/p/" + resProject + "/runs/20261124/download/results.json",
		"/p/" + resProject + "/runs/20261124-999999/download/results.json",
		"/p/..%2Fshop/runs/" + resRun + "/download/results.json",
	} {
		w := do(s, req(s, http.MethodGet, u, nil, true))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", u, w.Code)
		}
		if strings.Contains(w.Body.String(), "SECRET") || strings.Contains(w.Body.String(), `"baseUrl"`) {
			t.Errorf("%s leaked a file", u)
		}
	}
	// A literal ../ is cleaned by the router and never reaches the file.
	w := do(s, req(s, http.MethodGet, "/p/"+resProject+"/runs/"+resRun+"/download/../../secret.txt", nil, true))
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "SECRET") {
		t.Errorf("literal ../: status %d", w.Code)
	}
}

func TestExportZipEndpoint(t *testing.T) {
	s := resultsServer(t)
	if err := s.store.AppendIgnore(resProject, idBola, "accepted"); err != nil {
		t.Fatal(err)
	}
	w := do(s, req(s, http.MethodGet, "/p/"+resProject+"/export.zip", nil, true))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="`+resProject+`-authdiff.zip"` {
		t.Errorf("Content-Disposition %q", cd)
	}
	dir, names := unzip(t, w.Body.Bytes())
	if !strings.Contains(strings.Join(names, ","), "authdiff.yaml") {
		t.Errorf("entries %v", names)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ignoreFile)); !strings.Contains(string(b), idBola) { //nolint:gosec // G304: test temp dir
		t.Errorf("ignore file in zip = %q", b)
	}
	if w := do(s, req(s, http.MethodGet, "/p/nope/export.zip", nil, true)); w.Code != http.StatusNotFound {
		t.Errorf("unknown project: status %d", w.Code)
	}
	// A project whose settings cannot form a config yet.
	if err := s.store.Save(&Project{Name: "empty"}); err != nil {
		t.Fatal(err)
	}
	if w := do(s, req(s, http.MethodGet, "/p/empty/export.zip", nil, true)); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("incomplete project: status %d, want 422", w.Code)
	}
}

// --- Project history ------------------------------------------------------------

func TestProjectHistory(t *testing.T) {
	s := resultsServer(t)
	older := resultFixture()
	older.StartedAt = older.StartedAt.Add(-24 * time.Hour)
	older.Findings = older.Findings[:1]
	writeRun(t, s, resProject, "20261123-090000", older)
	// A run directory without results (failed early) and a stray file are skipped.
	if err := os.MkdirAll(filepath.Join(s.store.RunsDir(resProject), "20261124-120000"), 0o700); err != nil {
		t.Fatal(err)
	}

	code, body := get(t, s, "/p/"+resProject)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	newer := strings.Index(body, `href="`+resultsURL+`"`)
	old := strings.Index(body, `href="/p/`+resProject+`/runs/20261123-090000/results"`)
	if newer < 0 || old < 0 || newer > old {
		t.Fatalf("history links missing or not newest first (%d, %d)", newer, old)
	}
	if strings.Contains(body, "20261124-120000") {
		t.Error("run without results listed")
	}
	for _, want := range []string{
		"2026-11-24", "2026-11-23",
		`id="h-` + resRun + `">3<`, `id="h-20261123-090000">1<`, // active findings per run
		`action="/p/` + resProject + `/scan"`,
		`href="/p/` + resProject + `/settings"`,
		`href="/p/` + resProject + `/export.zip"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("project page lacks %q", want)
		}
	}

	// A project without runs says so.
	if err := s.store.Save(&Project{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	_, body = get(t, s, "/p/fresh")
	if !strings.Contains(body, `class="empty"`) {
		t.Error("empty history not shown")
	}
}

// TestSeverityKeys covers the sev.* keys built with printf in the
// templates, which TestI18nKeysComplete cannot see.
func TestSeverityKeys(t *testing.T) {
	cat, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, sev := range severities {
		for _, lang := range languages {
			if _, ok := cat[lang]["sev."+string(sev)]; !ok {
				t.Errorf("sev.%s missing in %s.json", sev, lang)
			}
		}
	}
}

// The export link has no download attribute: with it, browsers save the
// 422 explanation page as a file instead of showing it.
func TestExportLinkShowsErrors(t *testing.T) {
	s := resultsServer(t)
	noDownload := regexp.MustCompile(`export\.zip"[^>]*\bdownload\b`)
	for _, page := range []string{resultsURL, "/p/" + resProject} {
		_, body := get(t, s, page)
		if !strings.Contains(body, `href="/p/`+resProject+`/export.zip"`) {
			t.Errorf("%s: export link missing", page)
		}
		if noDownload.MatchString(body) {
			t.Errorf("%s: export link has a download attribute", page)
		}
	}
}

func writeStatus(t *testing.T, s *Server, id string, st runStatus) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.store.RunsDir(resProject), id, statusFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A stopped or failed run says so on its results page and in the history;
// a completed run and an older run without status.json show no notice.
func TestResultsRunStatus(t *testing.T) {
	s := resultsServer(t)
	en := s.cat["en"]
	stopped, failed := template.HTMLEscapeString(en["results.status.stopped"]), template.HTMLEscapeString(fmt.Sprintf(en["results.status.failed"], "rate limited"))
	_, body := get(t, s, resultsURL)
	if strings.Contains(body, stopped) || strings.Contains(body, `class="tag run-`) {
		t.Error("run without status.json shows a status")
	}

	writeStatus(t, s, resRun, runStatus{Status: "stopped"})
	if _, body = get(t, s, resultsURL); !strings.Contains(body, stopped) {
		t.Error("stopped run: notice missing")
	}
	if _, body = get(t, s, "/p/"+resProject); !strings.Contains(body, template.HTMLEscapeString(en["project.history.status.stopped"])) {
		t.Error("stopped run: history label missing")
	}

	writeStatus(t, s, resRun, runStatus{Status: "failed", Message: "rate limited"})
	if _, body = get(t, s, resultsURL); !strings.Contains(body, failed) {
		t.Error("failed run: notice with message missing")
	}
	if _, body = get(t, s, "/p/"+resProject); !strings.Contains(body, template.HTMLEscapeString(en["project.history.status.failed"])) {
		t.Error("failed run: history label missing")
	}

	writeStatus(t, s, resRun, runStatus{Status: "completed"})
	if _, body = get(t, s, resultsURL); strings.Contains(body, stopped) || strings.Contains(body, template.HTMLEscapeString(en["results.status.noresponse"])) {
		t.Error("completed run shows a status notice")
	}
}

// A scan in which no request got an HTTP response is not shown as clean.
func TestResultsNoResponseWarning(t *testing.T) {
	s := resultsServer(t)
	warn := template.HTMLEscapeString(s.cat["en"]["results.status.noresponse"])
	if _, body := get(t, s, resultsURL); strings.Contains(body, warn) {
		t.Error("warning shown for a scan with responses")
	}
	res := resultFixture()
	res.Findings, res.Matrix = nil, nil
	res.Stats = finding.Stats{Endpoints: 2, Requests: 4, Errors: 3, Blocked: 1}
	writeRun(t, s, resProject, "20261124-110000", res)
	_, body := get(t, s, "/p/"+resProject+"/runs/20261124-110000/results")
	if !strings.Contains(body, warn) || !strings.Contains(body, `role="alert"`) {
		t.Error("no-response warning missing")
	}
}
