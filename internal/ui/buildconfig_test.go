package ui

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

func TestBuildConfigMissingSecrets(t *testing.T) {
	p := sampleProject()
	_, err := BuildConfig(p, NewSecrets(), "")
	var miss ErrMissingSecrets
	if !errors.As(err, &miss) {
		t.Fatalf("err = %v, want ErrMissingSecrets", err)
	}
	if strings.Join(miss.Profiles, ",") != "alice,staging-admin" {
		t.Errorf("Profiles = %v", miss.Profiles)
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("message %q does not name the profile", err)
	}

	t.Setenv("AUTHDIFF_ALICE_TOKEN", "env-token-value")
	_, err = BuildConfig(p, NewSecrets(), "")
	if !errors.As(err, &miss) || strings.Join(miss.Profiles, ",") != "staging-admin" {
		t.Errorf("with env: err = %v", err)
	}
}

func TestBuildConfigValid(t *testing.T) {
	p := sampleProject()
	sec := NewSecrets()
	sec.Set(p.Name, "alice", Secret{Token: testToken})
	t.Setenv("AUTHDIFF_STAGING_ADMIN_USERNAME", "admin")
	t.Setenv("AUTHDIFF_STAGING_ADMIN_PASSWORD", "pw")
	c, err := BuildConfig(p, sec, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Filter.Exclude, []string{"DELETE /users/{id}"}) || !reflect.DeepEqual(c.Filter.Tags, []string{"orders"}) {
		t.Errorf("Filter = %+v", c.Filter)
	}
	if !c.Scope.AcknowledgeAuthorization {
		t.Error("Acknowledged not mapped to AcknowledgeAuthorization")
	}
	if c.Profiles["alice"].Auth.Token != testToken || c.Profiles["alice"].Name != "alice" {
		t.Errorf("alice = %+v", c.Profiles["alice"])
	}
	if a := c.Profiles["staging-admin"].Auth; a.Username != "admin" || a.Password != "pw" || a.Type != "basic" {
		t.Errorf("staging-admin auth = %+v", a)
	}
	if c.Target.Spec != p.SpecURL || c.Safety.Timeout != 7*time.Second || c.Safety.Rate != 3 ||
		c.Compare.SimilarityThreshold != 0.9 || c.Matrix["GET /admin/*"].Allow[0] != "admin" || len(c.Harvest) != 1 {
		t.Errorf("config = %+v", c)
	}
	if len(c.Rules.Dirs) != 0 || len(c.Rules.Disable) != 0 {
		t.Error("rules must not be set by the UI")
	}

	// An uploaded spec resolves inside the project directory.
	p.SpecFile = "spec.yaml"
	c, err = BuildConfig(p, sec, "/projects/staging-api")
	if err != nil {
		t.Fatal(err)
	}
	if c.Target.Spec != filepath.Join("/projects/staging-api", "spec.yaml") {
		t.Errorf("Spec = %q", c.Target.Spec)
	}

	// Validation errors surface.
	p.Acknowledged = false
	if _, err := BuildConfig(p, sec, ""); err == nil || !strings.Contains(err.Error(), "acknowledgeAuthorization") {
		t.Errorf("unacknowledged: err = %v", err)
	}
}

func TestPlaceholderConfig(t *testing.T) {
	p := sampleProject()
	c, err := PlaceholderConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Profiles["alice"].Auth.Token; got != "${env:AUTHDIFF_ALICE_TOKEN}" {
		t.Errorf("alice token = %q", got)
	}
	a := c.Profiles["staging-admin"].Auth
	if a.Username != "${env:AUTHDIFF_STAGING_ADMIN_USERNAME}" || a.Password != "${env:AUTHDIFF_STAGING_ADMIN_PASSWORD}" {
		t.Errorf("basic auth = %+v", a)
	}
	if c.Profiles["anonymous"].Auth.Token != "" {
		t.Error("none profile got a token")
	}
	p.SpecFile = "spec.json"
	c, err = PlaceholderConfig(p)
	if err != nil || c.Target.Spec != "spec.json" {
		t.Errorf("Spec = %q, %v", c.Target.Spec, err)
	}
	p.BaseURL = ""
	if _, err := PlaceholderConfig(p); err == nil {
		t.Error("invalid project produced a config")
	}
}

func TestEnsureDemoMatchesExample(t *testing.T) {
	st := newTestStore(t)
	sec := NewSecrets()
	p, err := EnsureDemo(st, sec, "http://localhost:8000")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Demo || p.Name != DemoName {
		t.Fatalf("demo project = %+v", p)
	}
	got, err := BuildConfig(p, sec, st.Dir(p.Name))
	if err != nil {
		t.Fatal(err)
	}

	env, err := demoEnvValues()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	want, err := config.Load(filepath.Join("..", "..", "examples", "authdiff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The UI has no output settings; the run writes its own reports.
	got.Output, want.Output = config.Output{}, config.Output{}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("demo config differs from the example:\n got %+v\nwant %+v", got, want)
	}

	// The demo is the one project whose tokens go to disk.
	b, err := os.ReadFile(filepath.Join(st.Dir(p.Name), demoSecretsFile))
	if err != nil || !strings.Contains(string(b), env["ALICE_TOKEN"]) {
		t.Errorf("demo-secrets.json = %q, %v", b, err)
	}
	pj, _ := os.ReadFile(filepath.Join(st.Dir(p.Name), "project.json"))
	if strings.Contains(string(pj), env["ALICE_TOKEN"]) {
		t.Error("project.json contains a token")
	}

	// Placeholders keep the example's variable names.
	pc, err := PlaceholderConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if tok := pc.Profiles["admin"].Auth.Token; tok != "${env:ADMIN_TOKEN}" {
		t.Errorf("demo placeholder = %q", tok)
	}
	if miss := NewSecrets().Missing(p); len(miss) != 0 {
		t.Errorf("Missing with example env set = %v", miss)
	}
}

func TestEnsureDemoIdempotent(t *testing.T) {
	st := newTestStore(t)
	p, err := EnsureDemo(st, NewSecrets(), "http://localhost:8000")
	if err != nil {
		t.Fatal(err)
	}
	p.Step = "plan"
	p.Safety.Rate = 2
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	sec := NewSecrets()
	q, err := EnsureDemo(st, sec, "http://127.0.0.1:8001/")
	if err != nil {
		t.Fatal(err)
	}
	if q.Step != "plan" || q.Safety.Rate != 2 || !q.CreatedAt.Equal(p.CreatedAt) {
		t.Errorf("EnsureDemo did not reuse the project: %+v", q)
	}
	if q.BaseURL != "http://127.0.0.1:8001" || q.SpecURL != "http://127.0.0.1:8001/openapi.json" ||
		!reflect.DeepEqual(q.AllowHosts, []string{"127.0.0.1:8001"}) {
		t.Errorf("lab URL not refreshed: %q %q %v", q.BaseURL, q.SpecURL, q.AllowHosts)
	}
	if s, ok := sec.Get(DemoName, "alice"); !ok || s.Token == "" {
		t.Error("demo tokens not loaded into Secrets")
	}
	list, _ := st.List()
	if len(list) != 1 {
		t.Errorf("List = %d projects, want 1", len(list))
	}
	if _, err := EnsureDemo(st, sec, "::bad"); err == nil {
		t.Error("EnsureDemo accepted an invalid lab URL")
	}
}

func TestEnsureDemoRefusesUserProject(t *testing.T) {
	st := newTestStore(t)
	if err := st.Save(&Project{Name: DemoName}); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureDemo(st, NewSecrets(), "http://localhost:8000"); err == nil {
		t.Error("EnsureDemo overwrote a non-demo project")
	}
}
