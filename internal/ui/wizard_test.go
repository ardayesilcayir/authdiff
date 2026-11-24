package ui

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

func loadInv(t *testing.T, c *config.Config) (*spec.Inventory, error) {
	t.Helper()
	return authdiff.LoadInventoryConfig(context.Background(), c, "", "test")
}

const petstore = "../../test/testdata/petstore.yaml"

// postMultipart builds an authenticated same-origin multipart POST with the
// CSRF token, the fields and, if fileName is set, a specFile part.
func postMultipart(t *testing.T, s *Server, target string, fields url.Values, fileName string, file []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf", s.csrf)
	for k, vs := range fields {
		for _, v := range vs {
			_ = mw.WriteField(k, v)
		}
	}
	if fileName != "" {
		fw, err := mw.CreateFormFile("specFile", fileName)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(file)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := req(s, http.MethodPost, target, &buf, true)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "http://127.0.0.1:7465")
	return r
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantRedirect(t *testing.T, w interface {
	Result() *http.Response
}, loc string) {
	t.Helper()
	res := w.Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != loc {
		t.Fatalf("status %d Location %q, want 303 %q", res.StatusCode, res.Header.Get("Location"), loc)
	}
}

// newProject creates project name through the form.
func newProject(t *testing.T, s *Server, name string) {
	t.Helper()
	wantRedirect(t, do(s, postForm(s, "/projects/new", url.Values{"name": {name}})), "/p/"+name+"/target")
}

// targetWithSpec runs the target step with an uploaded spec.
func targetWithSpec(t *testing.T, s *Server, name, file string, spec []byte) {
	t.Helper()
	w := do(s, postMultipart(t, s, "/p/"+name+"/target", url.Values{
		"baseUrl": {"http://127.0.0.1:8080"}, "ack": {"on"},
	}, file, spec))
	wantRedirect(t, w, "/p/"+name+"/endpoints")
}

func getProject(t *testing.T, s *Server, name string) *Project {
	t.Helper()
	p, err := s.store.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewProjectFlow(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "shop")
	if w := do(s, req(s, http.MethodGet, "/p/shop/target", nil, true)); w.Code != http.StatusOK {
		t.Fatalf("target page: %d", w.Code)
	}
	targetWithSpec(t, s, "shop", "petstore.yaml", readFile(t, petstore))
	p := getProject(t, s, "shop")
	if p.SpecFile != "spec.yaml" || strings.Join(p.AllowHosts, ",") != "127.0.0.1:8080" || !p.Acknowledged {
		t.Fatalf("after target: %+v", p)
	}

	w := do(s, req(s, http.MethodGet, "/p/shop/endpoints", nil, true))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/pets/{petId}") || !strings.Contains(w.Body.String(), "showPetById") {
		t.Fatalf("endpoints page %d:\n%s", w.Code, w.Body)
	}
	wantRedirect(t, do(s, postForm(s, "/p/shop/endpoints", url.Values{
		"ep": {"GET /pets", "GET /pets/{petId}", "PUT /pets/{petId}", "DELETE /pets/{petId}"},
	})), "/p/shop/profiles")

	w = do(s, req(s, http.MethodGet, "/p/shop/profiles", nil, true))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "p0.owns.petId") {
		t.Fatalf("profiles page %d lacks the petId suggestion", w.Code)
	}
	wantRedirect(t, do(s, postForm(s, "/p/shop/profiles", url.Values{
		"p0.name": {"admin"}, "p0.role": {"admin"}, "p0.auth": {"bearer"}, "p0.token": {"admin-token-0001"},
		"p1.name": {"alice"}, "p1.role": {"user"}, "p1.auth": {"bearer"}, "p1.token": {"alice-token-0002"}, "p1.owns.petId": {"1, 2"},
		"p2.name": {"bob"}, "p2.role": {"user"}, "p2.auth": {"apikey"}, "p2.authName": {"X-Key"}, "p2.authIn": {"header"}, "p2.token": {"bob-token-0003"},
		"p3.name": {"anonymous"}, "p3.role": {"none"}, "p3.auth": {"none"},
		"p4.name": {""},
	})), "/p/shop/settings")

	if w := do(s, req(s, http.MethodGet, "/p/shop/settings", nil, true)); w.Code != http.StatusOK {
		t.Fatalf("settings page: %d", w.Code)
	}
	wantRedirect(t, do(s, postForm(s, "/p/shop/settings", url.Values{
		"rate": {"3"}, "concurrency": {"2"}, "timeout": {"15"}, "threshold": {"0.9"},
		"ignoreFields": {"$.requestId\n$.ts"}, "m0.pattern": {"GET /admin/**"}, "m0.allow": {"admin"},
		"m1.pattern": {""},
	})), "/p/shop/plan")

	p = getProject(t, s, "shop")
	if strings.Join(p.Exclude, ",") != "POST /pets" {
		t.Errorf("Exclude = %v", p.Exclude)
	}
	if len(p.Profiles) != 4 || p.Profiles[1].Owns["petId"][1] != "2" {
		t.Errorf("Profiles = %+v", p.Profiles)
	}
	if p.Safety.Rate != 3 || p.Safety.Concurrency != 2 || p.Safety.TimeoutSec != 15 || p.Safety.AllowDestructive {
		t.Errorf("Safety = %+v", p.Safety)
	}
	if strings.Join(p.Matrix["GET /admin/**"], ",") != "admin" || len(p.IgnoreFields) != 2 || p.Threshold != 0.9 {
		t.Errorf("advanced = %v %v %v", p.Matrix, p.IgnoreFields, p.Threshold)
	}
	c, err := BuildConfig(p, s.secrets, s.store.Dir("shop"))
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if c.Profiles["bob"].Auth.Token != "bob-token-0003" || c.Profiles["bob"].Auth.Name != "X-Key" {
		t.Errorf("bob = %+v", c.Profiles["bob"])
	}

	// Overview and list pages.
	w = do(s, req(s, http.MethodGet, "/p/shop", nil, true))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `href="/p/shop/settings"`) {
		t.Errorf("overview %d", w.Code)
	}
	w = do(s, req(s, http.MethodGet, "/projects", nil, true))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `href="/p/shop"`) {
		t.Errorf("projects %d", w.Code)
	}
	if !strings.Contains(do(s, req(s, http.MethodGet, "/", nil, true)).Body.String(), `href="/p/shop"`) {
		t.Error("home does not list the project")
	}
}

func TestNewProjectValidation(t *testing.T) {
	s := testServer(t, Options{})
	if w := do(s, req(s, http.MethodGet, "/projects/new", nil, true)); w.Code != http.StatusOK {
		t.Fatalf("new page: %d", w.Code)
	}
	for _, name := range []string{"", "Bad Name", "../x"} {
		if w := do(s, postForm(s, "/projects/new", url.Values{"name": {name}})); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("name %q: %d", name, w.Code)
		}
	}
	newProject(t, s, "dup")
	if w := do(s, postForm(s, "/projects/new", url.Values{"name": {"dup"}})); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("duplicate: %d", w.Code)
	}
	if w := do(s, req(s, http.MethodGet, "/projects", nil, true)); w.Code != http.StatusOK {
		t.Errorf("list: %d", w.Code)
	}
	for _, path := range []string{"/p/nope/target", "/p/nope", "/p/Bad/settings"} {
		if w := do(s, req(s, http.MethodGet, path, nil, true)); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, w.Code)
		}
	}
}

func TestProjectsListEmptyDir(t *testing.T) {
	s := testServer(t, Options{ProjectsDir: filepath.Join(t.TempDir(), "not", "yet")})
	w := do(s, req(s, http.MethodGet, "/projects", nil, true))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestDeleteProject(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "gone")
	s.secrets.Set("gone", "alice", Secret{Token: "x"})
	if w := do(s, postForm(s, "/p/gone/delete", nil)); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("without confirmation: %d", w.Code)
	}
	wantRedirect(t, do(s, postForm(s, "/p/gone/delete", url.Values{"sure": {"yes"}})), "/projects")
	if _, err := s.store.Get("gone"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("project still there: %v", err)
	}
	if sec, _ := s.secrets.Get("gone", "alice"); sec.Token != "" {
		t.Error("secrets kept after delete")
	}
	if w := do(s, postForm(s, "/p/gone/delete", url.Values{"sure": {"yes"}})); w.Code != http.StatusNotFound {
		t.Errorf("second delete: %d", w.Code)
	}
}

func TestTargetRequiresAck(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	w := do(s, postMultipart(t, s, "/p/a/target", url.Values{"baseUrl": {"http://127.0.0.1:8080"}}, "s.yaml", readFile(t, petstore)))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), s.cat["en"]["target.err.ack"]) {
		t.Fatalf("status %d", w.Code)
	}
	if p := getProject(t, s, "a"); p.Acknowledged || p.BaseURL != "" {
		t.Errorf("saved despite error: %+v", p)
	}
}

func TestTargetRejectsUserinfo(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	for _, base := range []string{"http://user:pw@127.0.0.1:8080", "ftp://127.0.0.1", "not a url", ""} {
		w := do(s, postMultipart(t, s, "/p/a/target", url.Values{"baseUrl": {base}, "ack": {"on"}}, "s.yaml", readFile(t, petstore)))
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%q: status %d", base, w.Code)
		}
		if strings.Contains(w.Body.String(), "user:pw") {
			t.Errorf("%q: credentials echoed", base)
		}
	}
}

func TestTargetSpecChoices(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	cases := []struct {
		name   string
		fields url.Values
		file   string
	}{
		{"no spec", url.Values{"baseUrl": {"http://h:1"}, "ack": {"on"}}, ""},
		{"bad extension", url.Values{"baseUrl": {"http://h:1"}, "ack": {"on"}}, "spec.txt"},
		{"bad spec url", url.Values{"baseUrl": {"http://h:1"}, "ack": {"on"}, "specUrl": {"file:///etc/passwd"}}, ""},
		{"bad allow host", url.Values{"baseUrl": {"http://h:1"}, "ack": {"on"}, "specUrl": {"http://h:1/s"}, "allowHosts": {"h:1/x"}}, ""},
	}
	for _, c := range cases {
		if w := do(s, postMultipart(t, s, "/p/a/target", c.fields, c.file, []byte("x"))); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d", c.name, w.Code)
		}
	}
	// URL spec with explicit hosts.
	w := do(s, postMultipart(t, s, "/p/a/target", url.Values{
		"baseUrl": {"https://api.example.com"}, "ack": {"on"}, "specUrl": {"https://docs.example.com/openapi.json"},
		"allowHosts": {"api.example.com:443\n docs.example.com:443 "},
	}, "", nil))
	wantRedirect(t, w, "/p/a/endpoints")
	p := getProject(t, s, "a")
	if p.SpecURL != "https://docs.example.com/openapi.json" || strings.Join(p.AllowHosts, ",") != "api.example.com:443,docs.example.com:443" {
		t.Errorf("%+v", p)
	}
	// Default port when allowHosts is empty.
	w = do(s, postMultipart(t, s, "/p/a/target", url.Values{"baseUrl": {"https://api.example.com/v1"}, "ack": {"on"}, "specUrl": {"https://api.example.com/openapi.json"}}, "", nil))
	wantRedirect(t, w, "/p/a/endpoints")
	if p := getProject(t, s, "a"); strings.Join(p.AllowHosts, ",") != "api.example.com:443" {
		t.Errorf("AllowHosts = %v", p.AllowHosts)
	}
	// Keeping the uploaded spec: no new file, no URL.
	targetWithSpec(t, s, "a", "s.json", []byte(`{}`))
	w = do(s, postMultipart(t, s, "/p/a/target", url.Values{"baseUrl": {"http://127.0.0.1:9"}, "ack": {"on"}}, "", nil))
	wantRedirect(t, w, "/p/a/endpoints")
	if p := getProject(t, s, "a"); p.SpecFile != "spec.json" || p.SpecURL != "" {
		t.Errorf("spec not kept: %+v", p)
	}
}

func TestEndpointsBadSpec(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	targetWithSpec(t, s, "a", "bad.yaml", []byte("openapi: [unclosed\n  : : :"))
	w := do(s, req(s, http.MethodGet, "/p/a/endpoints", nil, true))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), s.cat["en"]["endpoints.err.load"]) {
		t.Fatalf("bad YAML: status %d\n%s", w.Code, w.Body)
	}
	if w := do(s, postForm(s, "/p/a/endpoints", url.Values{"ep": {"GET /x"}})); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("POST with bad spec: %d", w.Code)
	}

	const secret = "s3cr3tQueryValue"
	w = do(s, postMultipart(t, s, "/p/a/target", url.Values{
		"baseUrl": {"http://127.0.0.1:1"}, "ack": {"on"}, "specUrl": {"http://127.0.0.1:1/openapi.json?token=" + secret},
	}, "", nil))
	wantRedirect(t, w, "/p/a/endpoints")
	w = do(s, req(s, http.MethodGet, "/p/a/endpoints", nil, true))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unreachable URL: status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Error("spec URL query value shown on the endpoints page")
	}
	if !strings.Contains(w.Body.String(), "token=****") {
		t.Errorf("redacted URL missing:\n%s", w.Body)
	}
}

func TestEndpointsNeedTarget(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	if w := do(s, req(s, http.MethodGet, "/p/a/endpoints", nil, true)); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("status %d", w.Code)
	}
}

func TestEndpointsExcludeApplied(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	targetWithSpec(t, s, "a", "p.yaml", readFile(t, petstore))
	if w := do(s, postForm(s, "/p/a/endpoints", nil)); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("nothing selected: %d", w.Code)
	}
	wantRedirect(t, do(s, postForm(s, "/p/a/endpoints", url.Values{
		"ep": {"GET /pets", "GET /pets/{petId}", "PUT /pets/{petId}"}, "tag": {"pets"},
	})), "/p/a/profiles")
	p := getProject(t, s, "a")
	if strings.Join(p.Exclude, ",") != "POST /pets,DELETE /pets/{petId}" || strings.Join(p.Tags, ",") != "pets" {
		t.Fatalf("Exclude = %v Tags = %v", p.Exclude, p.Tags)
	}
	// The method-prefixed exclude removes exactly that operation.
	s.secrets.Set("a", "anon", Secret{})
	p.Profiles = []ProfileDef{{Name: "anon", Role: "none", AuthType: "none"}}
	c, err := BuildConfig(p, s.secrets, s.store.Dir("a"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := loadInv(t, c)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, e := range inv.Endpoints {
		keys = append(keys, e.Key())
	}
	if strings.Join(keys, ",") != "GET /pets,GET /pets/{petId},PUT /pets/{petId}" {
		t.Errorf("filtered inventory = %v", keys)
	}
	// The page shows the excluded rows unchecked.
	body := do(s, req(s, http.MethodGet, "/p/a/endpoints", nil, true)).Body.String()
	if !strings.Contains(body, `value="POST /pets">`) || strings.Contains(body, `value="POST /pets" checked`) {
		t.Errorf("POST /pets not shown unchecked")
	}
	if !strings.Contains(body, `value="GET /pets" checked`) {
		t.Errorf("GET /pets not shown checked")
	}
}

func TestGlobEscape(t *testing.T) {
	if got := escapeGlob(`GET /a/*/[x]?\`); got != `GET /a/\*/\[x\]\?\\` {
		t.Errorf("escapeGlob = %q", got)
	}
}

func TestTargetEscapesHostileSpec(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	hostile := `openapi: 3.0.3
info: {title: "<script>alert(1)</script>", version: "1"}
paths:
  /x<script>alert(2)</script>:
    get:
      operationId: "<img src=x onerror=alert(3)>"
      responses: {"200": {description: ok}}
`
	targetWithSpec(t, s, "a", "h.yaml", []byte(hostile))
	for _, path := range []string{"/p/a/endpoints", "/p/a/target", "/p/a/profiles"} {
		body := do(s, req(s, http.MethodGet, path, nil, true)).Body.String()
		for _, bad := range []string{"<script>alert", "<img src=x"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains unescaped %q", path, bad)
			}
		}
	}
	body := do(s, req(s, http.MethodGet, "/p/a/endpoints", nil, true)).Body.String()
	if !strings.Contains(body, "/x&lt;script&gt;alert(2)&lt;/script&gt;") {
		t.Errorf("hostile path not shown escaped:\n%s", body)
	}
}

func profileForm(name, token string) url.Values {
	return url.Values{"p0.name": {name}, "p0.orig": {name}, "p0.role": {"user"}, "p0.auth": {"bearer"}, "p0.token": {token}}
}

func TestProfilesKeepSecretWhenBlank(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", profileForm("alice", "first-token-AAAA"))), "/p/a/settings")
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", profileForm("alice", ""))), "/p/a/settings")
	if sec, _ := s.secrets.Get("a", "alice"); sec.Token != "first-token-AAAA" {
		t.Errorf("token = %q, want kept", sec.Token)
	}
	// Renaming moves the secret.
	f := profileForm("alice2", "")
	f.Set("p0.orig", "alice")
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", f)), "/p/a/settings")
	if sec, _ := s.secrets.Get("a", "alice2"); sec.Token != "first-token-AAAA" {
		t.Errorf("renamed token = %q", sec.Token)
	}
	if sec, _ := s.secrets.Get("a", "alice"); sec.Token != "" {
		t.Error("old name keeps the token")
	}
	// Removing a profile drops it and its secret.
	f = profileForm("alice2", "")
	f.Set("p1.name", "anon")
	f.Set("p1.role", "none")
	f.Set("p1.auth", "none")
	f.Set("p0.remove", "on")
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", f)), "/p/a/settings")
	if p := getProject(t, s, "a"); len(p.Profiles) != 1 || p.Profiles[0].Name != "anon" {
		t.Errorf("Profiles = %+v", p.Profiles)
	}
	if sec, _ := s.secrets.Get("a", "alice2"); sec.Token != "" {
		t.Error("removed profile keeps the token")
	}
}

func TestProfilesNeverEchoSecret(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	const tok = "tok-supersecret-WXYZ"
	f := profileForm("alice", tok)
	f.Set("p1.name", "admin")
	f.Set("p1.role", "admin")
	f.Set("p1.auth", "basic")
	f.Set("p1.username", "root-user-name")
	f.Set("p1.password", "root-password-9876")
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", f)), "/p/a/settings")
	body := do(s, req(s, http.MethodGet, "/p/a/profiles", nil, true)).Body.String()
	for _, secret := range []string{tok, "root-user-name", "root-password-9876"} {
		if strings.Contains(body, secret) {
			t.Errorf("page echoes %q", secret)
		}
	}
	if !strings.Contains(body, "•••• WXYZ") || !strings.Contains(body, "•••• 9876") {
		t.Errorf("mask missing")
	}
	// A rejected form does not echo the submitted token either.
	f.Set("p1.role", "superuser")
	w := do(s, postForm(s, "/p/a/profiles", f))
	if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), tok) {
		t.Errorf("422 page: status %d, echoes token: %v", w.Code, strings.Contains(w.Body.String(), tok))
	}
	// Only one user role: the same-role warning shows.
	if !strings.Contains(body, s.cat["en"]["profiles.warn.same_role"]) {
		t.Error("same-role warning missing")
	}
}

func TestProfilesValidation(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	cases := map[string]url.Values{
		"none":       {"p0.name": {""}},
		"bad name":   {"p0.name": {"Alice Smith"}, "p0.role": {"user"}, "p0.auth": {"none"}},
		"bad auth":   {"p0.name": {"a"}, "p0.role": {"user"}, "p0.auth": {"oauth"}},
		"bad in":     {"p0.name": {"a"}, "p0.role": {"user"}, "p0.auth": {"apikey"}, "p0.authIn": {"body"}},
		"duplicate":  {"p0.name": {"a"}, "p0.role": {"user"}, "p0.auth": {"none"}, "p1.name": {"a"}, "p1.role": {"user"}, "p1.auth": {"none"}},
		"owns param": {"p0.name": {"a"}, "p0.role": {"user"}, "p0.auth": {"none"}, "p0.ownsParam": {"x y"}, "p0.ownsIds": {"1"}},
	}
	for name, f := range cases {
		if w := do(s, postForm(s, "/p/a/profiles", f)); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	// Custom owned-ID parameter and identifiers.
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", url.Values{
		"p0.name": {"a"}, "p0.role": {"user"}, "p0.auth": {"cookie"}, "p0.authName": {"sid"}, "p0.token": {"t"},
		"p0.ownsParam": {"orderId"}, "p0.ownsIds": {"7,8"}, "p0.ids": {"a@example.com, a"},
	})), "/p/a/settings")
	p := getProject(t, s, "a")
	if strings.Join(p.Profiles[0].Owns["orderId"], ",") != "7,8" || len(p.Profiles[0].Identifiers) != 2 || p.Profiles[0].AuthName != "sid" {
		t.Errorf("%+v", p.Profiles[0])
	}
}

func TestProfilesTemplate(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", url.Values{"action": {"template"}, "p0.name": {""}})), "/p/a/profiles")
	p := getProject(t, s, "a")
	var names []string
	for _, pd := range p.Profiles {
		names = append(names, pd.Name+":"+pd.Role)
	}
	if strings.Join(names, ",") != "admin:admin,alice:user,bob:user,anonymous:none" {
		t.Errorf("template profiles = %v", names)
	}
	// Applying it again does not duplicate.
	wantRedirect(t, do(s, postForm(s, "/p/a/profiles", url.Values{"action": {"template"}})), "/p/a/profiles")
	if p := getProject(t, s, "a"); len(p.Profiles) != 4 {
		t.Errorf("%d profiles after second template", len(p.Profiles))
	}
	body := do(s, req(s, http.MethodGet, "/p/a/profiles", nil, true)).Body.String()
	if strings.Contains(body, s.cat["en"]["profiles.warn.same_role"]) {
		t.Error("same-role warning shown with two users")
	}
}

func TestDestructiveRequiresConfirm(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	base := url.Values{"rate": {"5"}, "concurrency": {"4"}, "timeout": {"10"}, "destructive": {"on"}}
	for _, confirm := range []string{"", "yes", "anladim", "I understand it"} {
		f := url.Values{}
		for k, v := range base {
			f[k] = v
		}
		f.Set("confirm", confirm)
		if w := do(s, postForm(s, "/p/a/settings", f)); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("confirm %q: status %d", confirm, w.Code)
		}
		if getProject(t, s, "a").Safety.AllowDestructive {
			t.Fatalf("confirm %q turned destructive mode on", confirm)
		}
	}
	for _, confirm := range []string{"anladım", "  ANLADIM ", "I understand", "i UNDERSTAND"} {
		f := url.Values{"rate": {"5"}, "concurrency": {"4"}, "timeout": {"10"}, "destructive": {"on"}, "confirm": {confirm}}
		wantRedirect(t, do(s, postForm(s, "/p/a/settings", f)), "/p/a/plan")
		if !getProject(t, s, "a").Safety.AllowDestructive {
			t.Errorf("confirm %q did not turn destructive mode on", confirm)
		}
		f = url.Values{"rate": {"5"}, "concurrency": {"4"}, "timeout": {"10"}}
		wantRedirect(t, do(s, postForm(s, "/p/a/settings", f)), "/p/a/plan")
		if getProject(t, s, "a").Safety.AllowDestructive {
			t.Error("unchecking did not turn destructive mode off")
		}
	}
}

func TestDemoAlsoRequiresConfirm(t *testing.T) {
	s := testServer(t, Options{LabURL: "http://127.0.0.1:8000"})
	wantRedirect(t, do(s, postForm(s, "/demo", nil)), "/p/"+DemoName+"/plan")
	p := getProject(t, s, DemoName)
	if !p.Demo || p.Safety.AllowDestructive {
		t.Fatalf("demo = %+v", p.Safety)
	}
	body := do(s, req(s, http.MethodGet, "/p/"+DemoName+"/settings", nil, true)).Body.String()
	if !strings.Contains(body, template.HTMLEscapeString(s.cat["en"]["settings.destructive.demo"])) {
		t.Error("demo warning missing")
	}
	w := do(s, postForm(s, "/p/"+DemoName+"/settings", url.Values{"rate": {"5"}, "concurrency": {"4"}, "timeout": {"10"}, "destructive": {"on"}}))
	if w.Code != http.StatusUnprocessableEntity || getProject(t, s, DemoName).Safety.AllowDestructive {
		t.Errorf("demo without confirm: status %d", w.Code)
	}
	wantRedirect(t, do(s, postForm(s, "/p/"+DemoName+"/settings", url.Values{"rate": {"5"}, "concurrency": {"4"}, "timeout": {"10"}, "destructive": {"on"}, "confirm": {"anladım"}})), "/p/"+DemoName+"/plan")
	if !getProject(t, s, DemoName).Safety.AllowDestructive {
		t.Error("demo with confirm stayed safe")
	}
	// The demo again: reuses the project.
	wantRedirect(t, do(s, postForm(s, "/demo", nil)), "/p/"+DemoName+"/plan")
}

func TestDemoBadLab(t *testing.T) {
	s := testServer(t, Options{})
	s.opts.LabURL = "::bad"
	if w := do(s, postForm(s, "/demo", nil)); w.Code != http.StatusInternalServerError {
		t.Errorf("status %d", w.Code)
	}
}

func TestSettingsValidation(t *testing.T) {
	s := testServer(t, Options{})
	newProject(t, s, "a")
	ok := url.Values{"rate": {"5"}, "concurrency": {"4"}, "timeout": {"10"}}
	bad := map[string][2]string{
		"rate":        {"rate", "0"},
		"rate nan":    {"rate", "x"},
		"concurrency": {"concurrency", "0"},
		"timeout":     {"timeout", "-1"},
		"threshold":   {"threshold", "1.5"},
		"proxy":       {"proxy", "ftp://p"},
		"proxy creds": {"proxy", "http://u:p@proxy:8080"},
		"matrix":      {"m0.pattern", "GET"},
	}
	for name, kv := range bad {
		f := url.Values{}
		for k, v := range ok {
			f[k] = v
		}
		f.Set(kv[0], kv[1])
		w := do(s, postForm(s, "/p/a/settings", f))
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d", name, w.Code)
		}
		if strings.Contains(w.Body.String(), "u:p@") {
			t.Errorf("%s: proxy credentials echoed", name)
		}
	}
	f := url.Values{"rate": {"2.5"}, "concurrency": {"1"}, "timeout": {"30"}, "proxy": {"http://127.0.0.1:8081"}, "insecure": {"on"},
		"m0.pattern": {"GET /orders/{orderId}"}, "m0.allow": {"owner", "admin"}}
	wantRedirect(t, do(s, postForm(s, "/p/a/settings", f)), "/p/a/plan")
	p := getProject(t, s, "a")
	if !p.Safety.Insecure || p.Safety.Proxy != "http://127.0.0.1:8081" || strings.Join(p.Matrix["GET /orders/{orderId}"], ",") != "owner,admin" {
		t.Errorf("%+v %v", p.Safety, p.Matrix)
	}
	body := do(s, req(s, http.MethodGet, "/p/a/settings", nil, true)).Body.String()
	if !strings.Contains(body, `value="GET /orders/{orderId}"`) || !strings.Contains(body, s.cat["en"]["settings.insecure.warn"]) {
		t.Error("settings page does not show the saved matrix row or the TLS warning")
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/p/a/target?x=1": "/p/a/target?x=1",
		"/":               "/",
		"//evil.com":      "/",
		"/\t/evil.com":    "/",
		"/\n/evil.com":    "/",
		"/\x7f/evil.com":  "/",
		`/\evil.com`:      "/",
		"http://evil.com": "/",
		"evil.com":        "/",
		"":                "/",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDynamicI18nKeys covers the keys templates build at run time, which
// TestI18nKeysComplete cannot see.
func TestDynamicI18nKeys(t *testing.T) {
	cat, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range roles {
		keys = append(keys, "profiles.role."+r)
	}
	for _, a := range authTypes {
		keys = append(keys, "profiles.auth."+a)
	}
	for _, st := range wizardSteps {
		keys = append(keys, st.Key, "wizard.step."+st.ID)
	}
	keys = append(keys, "projects.title", "newproject.title", "project.title",
		"project.history.status.stopped", "project.history.status.failed")
	for _, k := range keys {
		for _, lang := range languages {
			if _, ok := cat[lang][k]; !ok {
				t.Errorf("%s missing in %s.json", k, lang)
			}
		}
	}
}

// The demo's lab tokens are the one secret on disk (demo-secrets.json): a
// restarted server reads them back, so the demo needs no credentials.
func TestDemoSecretsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s := runServer(t, Options{ProjectsDir: dir, LabURL: "http://127.0.0.1:8000"})
	wantRedirect(t, do(s, postForm(s, "/demo", nil)), "/p/"+DemoName+"/plan")

	// A new Server and Secrets on the same directory: a restart.
	s2 := runServer(t, Options{ProjectsDir: dir, LabURL: "http://127.0.0.1:8000"})
	if body := do(s2, req(s2, http.MethodGet, "/p/"+DemoName, nil, true)).Body.String(); strings.Contains(body, template.HTMLEscapeString(s2.cat["en"]["profiles.warn.missing"])) {
		t.Error("overview after restart asks for credentials")
	}
	s2.runs.scan = func(context.Context, authdiff.ScanOptions) (*authdiff.Result, error) {
		return nil, errors.New("lab not running")
	}
	w := do(s2, postForm(s2, "/p/"+DemoName+"/scan", nil))
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/p/"+DemoName+"/runs/") {
		t.Fatalf("scan after restart: status %d Location %q, want a run", w.Code, loc)
	}
	waitRun(t, s2, strings.TrimPrefix(loc, "/p/"+DemoName+"/runs/"))

	// A credential cleared by hand stays cleared (memory wins over the file).
	s2.secrets.Set(DemoName, "alice", Secret{})
	if body := do(s2, req(s2, http.MethodGet, "/p/"+DemoName, nil, true)).Body.String(); !strings.Contains(body, "<code>alice</code>") {
		t.Error("cleared demo credential was reloaded from disk")
	}
}
