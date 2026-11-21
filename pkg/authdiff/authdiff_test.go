package authdiff

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

func ptr[T any](v T) *T { return &v }

func TestLoadConfigAppliesOverrides(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	cfg, err := LoadConfig(p, Overrides{
		Rate: ptr(7.5), Concurrency: ptr(9), AllowDestructive: ptr(true), Insecure: ptr(true),
		FailOn: ptr("medium"), Formats: []string{"sarif", "html"}, OutputDir: ptr("x"),
		Include: []string{"/orders/**"}, Exclude: []string{"/admin/**"}, Tags: []string{"orders"},
		RuleDirs: []string{"custom"},
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	s := cfg.Safety
	if s.Rate != 7.5 || s.Concurrency != 9 || !s.AllowDestructive || !s.Insecure {
		t.Errorf("safety = %+v", s)
	}
	if cfg.Output.FailOn != "medium" || strings.Join(cfg.Output.Formats, ",") != "sarif,html" || cfg.Output.Dir != "x" {
		t.Errorf("output = %+v", cfg.Output)
	}
	f := cfg.Filter
	if f.Include[0] != "/orders/**" || f.Exclude[0] != "/admin/**" || f.Tags[0] != "orders" {
		t.Errorf("filter = %+v", f)
	}
	if len(cfg.Rules.Dirs) != 1 || cfg.Rules.Dirs[0] != "custom" {
		t.Errorf("rule dirs = %v", cfg.Rules.Dirs)
	}
	want := filepath.Join(filepath.Dir(p), "openapi.yaml")
	if cfg.Target.Spec != want {
		t.Errorf("spec = %q, want %q (relative to config dir)", cfg.Target.Spec, want)
	}
	if cfg.Safety.Timeout == 0 {
		t.Error("defaults not applied")
	}
}

func TestLoadConfigValidatesOverrides(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	if _, err := LoadConfig(p, Overrides{FailOn: ptr("bogus")}); err == nil {
		t.Error("bad --fail-on accepted")
	}
	if _, err := LoadConfig(p, Overrides{Formats: []string{"pdf"}}); err == nil {
		t.Error("bad --format accepted")
	}
	if _, err := LoadConfig(p, Overrides{Rate: ptr(-1.0)}); err == nil {
		t.Error("negative --rate accepted")
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"), Overrides{}); err == nil {
		t.Error("missing config accepted")
	}
}

func TestLoadConfigKeepsSpecURL(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	data, _ := os.ReadFile(p)
	data = []byte(strings.Replace(string(data), "./openapi.yaml", api.URL+"/openapi.yaml", 1))
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target.Spec != api.URL+"/openapi.yaml" {
		t.Errorf("spec URL rewritten: %q", cfg.Target.Spec)
	}
}

func writeRule(t *testing.T, dir, name, id string) {
	t.Helper()
	src := `id: ` + id + `
name: Custom
owasp: "API1:2023"
severity: low
applies: { methods: [GET] }
steps:
  - { name: me, as: any_user, use: self }
match: me.ok
`
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRules(t *testing.T) {
	rs, err := LoadRules(nil, nil)
	if err != nil || len(rs) != 8 {
		t.Fatalf("builtin = %d rules, err %v", len(rs), err)
	}

	custom := t.TempDir()
	writeRule(t, custom, "c.yaml", "AD-CUSTOM-001")
	rs, err = LoadRules([]string{custom}, []string{"AD-LEAK-001"})
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	ids := map[string]bool{}
	for _, r := range rs {
		ids[r.ID] = true
	}
	if len(rs) != 8 || !ids["AD-CUSTOM-001"] || ids["AD-LEAK-001"] {
		t.Errorf("ids = %v", ids)
	}

	if _, err := LoadRules(nil, []string{"AD-NOPE-001"}); err == nil || !strings.Contains(err.Error(), "AD-NOPE-001") {
		t.Errorf("unknown disable id: err = %v", err)
	}

	dup := t.TempDir()
	writeRule(t, dup, "dup.yaml", "AD-BOLA-001")
	_, err = LoadRules([]string{dup}, nil)
	if err == nil || !strings.Contains(err.Error(), "AD-BOLA-001") ||
		!strings.Contains(err.Error(), "builtin/bola-read.yaml") || !strings.Contains(err.Error(), "dup.yaml") {
		t.Errorf("duplicate id: err = %v", err)
	}

	if _, err := LoadRules([]string{filepath.Join(custom, "missing")}, nil); err == nil {
		t.Error("missing rules dir accepted")
	}
}

func TestScanFindsBOLA(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	res, err := Scan(context.Background(), ScanOptions{ConfigPath: p, Version: "1.2.3"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !res.FailsAt(finding.High) {
		t.Fatalf("want a high finding, got %+v", res.Findings)
	}
	var bola bool
	for _, f := range res.Findings {
		if f.RuleID == "AD-BOLA-001" {
			bola = true
		}
	}
	if !bola {
		t.Errorf("no AD-BOLA-001 finding: %+v", res.Findings)
	}
	if res.Target != api.URL || res.Tool.Version != "1.2.3" {
		t.Errorf("header = %+v / %+v", res.Target, res.Tool)
	}
	if strings.Contains(res.SpecPath, `\`) || !strings.HasSuffix(res.SpecPath, "openapi.yaml") {
		t.Errorf("spec path = %q, want forward-slash relative path", res.SpecPath)
	}
	if res.Stats.Requests == 0 {
		t.Error("no requests counted")
	}
}

func TestScanAppliesBaseline(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	res, err := Scan(context.Background(), ScanOptions{ConfigPath: p})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range res.Findings {
		lines = append(lines, f.ID+" # "+f.RuleID)
	}
	ignore := filepath.Join(t.TempDir(), ".authdiff-ignore")
	if err := os.WriteFile(ignore, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = Scan(context.Background(), ScanOptions{ConfigPath: p, IgnoreFile: ignore})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 || len(res.Active()) != 0 {
		t.Errorf("active after baseline = %d of %d", len(res.Active()), len(res.Findings))
	}

	if err := os.WriteFile(ignore, []byte("not-an-id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(context.Background(), ScanOptions{ConfigPath: p, IgnoreFile: ignore}); err == nil {
		t.Error("bad ignore file accepted")
	}
}

func TestScanFilterOverride(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	res, err := Scan(context.Background(), ScanOptions{ConfigPath: p, Overrides: Overrides{Exclude: []string{"/orders/**"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Endpoints != 0 || len(res.Findings) != 0 || api.hits.Load() != 0 {
		t.Errorf("excluded endpoint scanned: %+v, hits %d", res.Stats, api.hits.Load())
	}
}

func TestScanCanceledReturnsPartial(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Scan(ctx, ScanOptions{ConfigPath: p})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res == nil {
		t.Fatal("no partial result")
	}
}

func TestPlanNoNetwork(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	plan, err := Plan(ScanOptions{ConfigPath: p})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan) == 0 {
		t.Fatal("empty plan")
	}
	if api.hits.Load() != 0 {
		t.Errorf("plan sent %d requests", api.hits.Load())
	}
	var sawBOLA bool
	for _, pr := range plan {
		if pr.RuleID == "AD-BOLA-001" && pr.Path == "/orders/101" {
			sawBOLA = true
		}
	}
	if !sawBOLA {
		t.Errorf("plan = %+v", plan)
	}
}

func TestDisplaySpecPath(t *testing.T) {
	if got := displaySpecPath("https://h/openapi.json"); got != "https://h/openapi.json" {
		t.Errorf("url = %q", got)
	}
	wd, _ := os.Getwd()
	if got := displaySpecPath(filepath.Join(wd, "a", "b.yaml")); got != "a/b.yaml" {
		t.Errorf("file = %q", got)
	}
}
