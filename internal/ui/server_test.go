package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// freePort returns a port that was free a moment ago.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func TestListenOnlyLoopback(t *testing.T) {
	s := testServer(t, Options{Port: freePort(t)})
	u, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.ln.Close() }()
	addr := s.ln.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("listening on %v, want 127.0.0.1", addr.IP)
	}
	want := fmt.Sprintf("http://127.0.0.1:%d/?key=%s", addr.Port, s.key)
	if u != want {
		t.Errorf("url = %q, want %q", u, want)
	}
	if len(s.key) != 64 {
		t.Errorf("key length %d, want 64 hex chars", len(s.key))
	}
}

func TestListenFallsBackToNextPort(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	p := busy.Addr().(*net.TCPAddr).Port
	s := testServer(t, Options{Port: p})
	u, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.ln.Close() }()
	got := s.ln.Addr().(*net.TCPAddr).Port
	if got <= p || got > p+maxPortTries-1 {
		t.Errorf("port %d, want in (%d, %d]", got, p, p+maxPortTries-1)
	}
	if !strings.Contains(u, fmt.Sprintf(":%d/", got)) {
		t.Errorf("url %q does not use port %d", u, got)
	}
	// The Host check follows the port actually bound.
	r := req(s, http.MethodGet, "/healthz", nil, true)
	r.Host = fmt.Sprintf("127.0.0.1:%d", got)
	if w := do(s, r); w.Code != http.StatusOK {
		t.Errorf("Host on bound port: %d", w.Code)
	}
}

func TestListenGivesUpAfterTries(t *testing.T) {
	// Occupy a run of ports; if any of them is taken by someone else the
	// test still holds since Listen must fail on all of them.
	base := freePort(t)
	var held []net.Listener
	for i := range maxPortTries {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
		if err != nil {
			continue
		}
		held = append(held, l)
	}
	defer func() {
		for _, l := range held {
			_ = l.Close()
		}
	}()
	if len(held) < maxPortTries {
		t.Skip("could not reserve a run of ports")
	}
	s := testServer(t, Options{Port: base})
	if _, err := s.Listen(); err == nil {
		_ = s.ln.Close()
		t.Fatal("Listen succeeded with every port busy")
	}
}

func TestServeShutsDownOnCancel(t *testing.T) {
	s := testServer(t, Options{Port: freePort(t)})
	u, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	hooked := make(chan struct{})
	s.OnShutdown(func(context.Context) { close(hooked) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	// Real round trip: key login then home page through the cookie jar.
	jar := &memJar{}
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.RawQuery != "" {
		t.Errorf("after login: status %d url %s", resp.StatusCode, resp.Request.URL)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	select {
	case <-hooked:
	default:
		t.Error("shutdown hook not called")
	}
}

// memJar is a minimal cookie jar keyed by host.
type memJar struct{ c []*http.Cookie }

func (j *memJar) SetCookies(_ *url.URL, cs []*http.Cookie) { j.c = append(j.c, cs...) }
func (j *memJar) Cookies(*url.URL) []*http.Cookie          { return j.c }

func TestHomeShowsLabStatus(t *testing.T) {
	lab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(`{"openapi":"3.0.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	s := testServer(t, Options{LabURL: lab.URL})
	r := req(s, http.MethodGet, "/", nil, true)
	r.Header.Set("Accept-Language", "en")
	body := do(s, r).Body.String()
	running := fmt.Sprintf(s.cat["en"]["home.lab.running"], lab.URL)
	stopped := fmt.Sprintf(s.cat["en"]["home.lab.stopped"], lab.URL)
	if !strings.Contains(body, running) {
		t.Errorf("running lab not shown as running:\n%s", body)
	}
	if strings.Contains(body, stopped) {
		t.Error("running lab shown as stopped")
	}

	lab.Close()
	body = do(s, r).Body.String()
	if !strings.Contains(body, stopped) {
		t.Errorf("stopped lab not shown as stopped:\n%s", body)
	}
	if !strings.Contains(body, "docker compose up -d --build --wait vuln-lab") || !strings.Contains(body, "uvicorn app.main:app") {
		t.Error("start commands missing for a stopped lab")
	}
}

func TestCheckLab(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			http.NotFound(w, r)
		}
	}))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ok.URL+"/openapi.json", http.StatusFound)
	}))
	defer redirect.Close()
	ctx := context.Background()
	localhostURL := strings.Replace(ok.URL, "127.0.0.1", "localhost", 1)
	for u, want := range map[string]bool{
		ok.URL:                     true,
		ok.URL + "/":               true,
		localhostURL:               true,
		bad.URL:                    false,
		redirect.URL:               false,
		"http://example.com":       false,
		"http://10.0.0.1:8000":     false,
		"ftp://127.0.0.1:8000":     false,
		"::not a url":              false,
		"http://127.0.0.1:1":       false,
		"http://127.0.0.1.nip.io/": false,
	} {
		if got := CheckLab(ctx, u); got != want {
			t.Errorf("CheckLab(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestLanguageNegotiation(t *testing.T) {
	s := testServer(t, Options{})
	tr, en := html.EscapeString(s.cat["tr"]["home.title"]), html.EscapeString(s.cat["en"]["home.title"])
	if tr == en {
		t.Fatal("home.title is the same in both languages")
	}
	cases := []struct {
		name, accept, cookie, want string
	}{
		{"default", "", "", "en"},
		{"accept tr-TR", "tr-TR,tr;q=0.9,en;q=0.8", "", "tr"},
		{"accept q order", "de;q=1,en;q=0.5,tr;q=0.9", "", "tr"},
		{"accept en", "en-US", "", "en"},
		{"accept unknown", "de-DE", "", "en"},
		{"cookie wins", "tr-TR", "en", "en"},
		{"cookie tr", "en", "tr", "tr"},
		{"bad cookie ignored", "tr", "xx", "tr"},
	}
	for _, c := range cases {
		r := req(s, http.MethodGet, "/", nil, true)
		if c.accept != "" {
			r.Header.Set("Accept-Language", c.accept)
		}
		if c.cookie != "" {
			r.AddCookie(&http.Cookie{Name: langCookie, Value: c.cookie}) //nolint:gosec // G124: request cookie in a test
		}
		body := do(s, r).Body.String()
		want := map[string]string{"tr": tr, "en": en}[c.want]
		if !strings.Contains(body, want) || !strings.Contains(body, `<html lang="`+c.want+`"`) {
			t.Errorf("%s: page not in %s", c.name, c.want)
		}
	}
}

func TestLangPostSetsCookie(t *testing.T) {
	s := testServer(t, Options{})
	w := do(s, postForm(s, "/lang", url.Values{"lang": {"tr"}, "next": {"/p/demo/target?x=1"}}))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/p/demo/target?x=1" {
		t.Errorf("status %d Location %q", w.Code, w.Header().Get("Location"))
	}
	set := w.Header().Get("Set-Cookie")
	if !strings.Contains(set, langCookie+"=tr") || !strings.Contains(set, "SameSite=Strict") {
		t.Errorf("Set-Cookie = %q", set)
	}
	for _, next := range []string{"//evil.com/", "http://evil.com/", `/\evil.com`, ""} {
		w := do(s, postForm(s, "/lang", url.Values{"lang": {"en"}, "next": {next}}))
		if loc := w.Header().Get("Location"); loc != "/" {
			t.Errorf("next %q: Location %q, want /", next, loc)
		}
	}
	if w := do(s, postForm(s, "/lang", url.Values{"lang": {"de"}})); w.Code != http.StatusBadRequest {
		t.Errorf("unknown lang: status %d, want 400", w.Code)
	}
}

func TestI18nKeysComplete(t *testing.T) {
	cat, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]string) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	trKeys, enKeys := keys(cat["tr"]), keys(cat["en"])
	if strings.Join(trKeys, ",") != strings.Join(enKeys, ",") {
		t.Errorf("tr and en key sets differ:\ntr: %v\nen: %v", trKeys, enKeys)
	}
	for lang, m := range cat {
		for k, v := range m {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %s is empty", lang, k)
			}
		}
	}

	used := map[string]bool{}
	tmplKey := regexp.MustCompile(`call \$?\.T "([^"]+)"`)
	err = fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(templateFS, p)
		if err != nil {
			return err
		}
		for _, m := range tmplKey.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Keys passed from Go code: T("..."), msgKey: "...".
	goKey := regexp.MustCompile(`(?:\.T\(|Key: )"([a-z][a-z0-9_.]+)"`)
	gofiles, _ := filepath.Glob("*.go")
	for _, f := range gofiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: package source files
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range goKey.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
	}
	if len(used) < 10 {
		t.Fatalf("found only %d used keys; the scan is broken", len(used))
	}
	for k := range used {
		for _, lang := range []string{"tr", "en"} {
			if _, ok := cat[lang][k]; !ok {
				t.Errorf("key %q used but missing in %s.json", k, lang)
			}
		}
	}
	tf := translator(cat["en"])
	if got := tf("no.such.key"); got != "no.such.key" {
		t.Errorf("missing key renders %q, want the key", got)
	}
}

func TestNoInnerHTML(t *testing.T) {
	banned := regexp.MustCompile(`innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function`)
	for _, root := range []fs.FS{staticFS, templateFS} {
		err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(root, p)
			if err != nil {
				return err
			}
			if m := banned.Find(b); m != nil {
				t.Errorf("%s uses %s", p, m)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestHealthz(t *testing.T) {
	s := testServer(t, Options{Version: "1.2.3"})
	w := do(s, req(s, http.MethodGet, "/healthz", nil, true))
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if got["status"] != "ok" || got["version"] != "1.2.3" {
		t.Errorf("healthz = %v", got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q", ct)
	}
}

func TestHomeEscapesAndCarriesCSRF(t *testing.T) {
	s := testServer(t, Options{Version: `<script>x</script>`})
	body := do(s, req(s, http.MethodGet, "/", nil, true)).Body.String()
	if strings.Contains(body, "<script>x</script>") {
		t.Error("version printed unescaped")
	}
	if !strings.Contains(body, `name="csrf" value="`+s.csrf+`"`) {
		t.Error("language form lacks the CSRF token")
	}
	if !strings.Contains(body, `src="/static/app.js"`) || !strings.Contains(body, `href="/static/app.css"`) {
		t.Error("assets not linked")
	}
}

func TestNewDefaults(t *testing.T) {
	s, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.opts.Port != DefaultPort || s.opts.LabURL != DefaultLabURL || s.opts.ProjectsDir == "" || s.opts.Log == nil {
		t.Errorf("defaults not applied: %+v", s.opts)
	}
	s2 := testServer(t, Options{})
	if s.key == s2.key || s.csrf == s.key {
		t.Error("keys are not random or the CSRF token equals the key")
	}
}
