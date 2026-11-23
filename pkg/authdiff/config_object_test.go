package authdiff

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

// objectConfig returns the in-memory config equivalent to writeProject's
// file, with the spec path left relative.
func objectConfig(t *testing.T, api *miniAPI) *config.Config {
	t.Helper()
	cfg, err := config.Load(writeProject(t, api, ""))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func findingIDs(res *Result) []string {
	ids := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}

func TestScanWithConfigObjectMatchesFile(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	fromFile, err := Scan(context.Background(), ScanOptions{ConfigPath: p})
	if err != nil {
		t.Fatalf("file scan: %v", err)
	}

	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	// Spare capacity: an append to the caller's slice would alias it.
	cfg.Rules.Dirs = make([]string, 0, 4)
	snapshot, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Rules.Dirs = []string{}
	rate := 1000.0
	var mu sync.Mutex
	var events []Progress
	fromObj, err := Scan(context.Background(), ScanOptions{
		Config:    cfg,
		BaseDir:   filepath.Dir(p),
		Overrides: Overrides{Rate: &rate, RuleDirs: []string{t.TempDir()}},
		OnProgress: func(pr Progress) {
			mu.Lock()
			events = append(events, pr)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("object scan: %v", err)
	}
	if a, b := findingIDs(fromFile), findingIDs(fromObj); !reflect.DeepEqual(a, b) {
		t.Errorf("finding IDs differ:\nfile   %v\nobject %v", a, b)
	}
	if !reflect.DeepEqual(cfg, snapshot) {
		t.Errorf("caller's config changed:\n got %+v\nwant %+v", cfg, snapshot)
	}
	if len(events) == 0 {
		t.Fatal("no progress events")
	}
	last := events[len(events)-1]
	if !last.Done || last.Planned == 0 || last.Sent != fromObj.Stats.Requests {
		t.Errorf("last event = %+v, stats %+v", last, fromObj.Stats)
	}
}

func TestScanBothConfigSourcesError(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	cfg := objectConfig(t, api)
	want := "authdiff: set ConfigPath or Config, not both"
	if _, err := Scan(context.Background(), ScanOptions{ConfigPath: p, Config: cfg}); err == nil || err.Error() != want {
		t.Errorf("Scan err = %v, want %q", err, want)
	}
	if _, err := PlanContext(context.Background(), ScanOptions{ConfigPath: p, Config: cfg}); err == nil || err.Error() != want {
		t.Errorf("PlanContext err = %v, want %q", err, want)
	}
}

func TestConfigObjectRelativeSpecUsesBaseDir(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	cfg := objectConfig(t, api)
	if cfg.Target.Spec != "./openapi.yaml" {
		t.Fatalf("spec = %q", cfg.Target.Spec)
	}
	plan, err := PlanContext(context.Background(), ScanOptions{Config: cfg, BaseDir: filepath.Dir(p)})
	if err != nil {
		t.Fatalf("PlanContext with BaseDir: %v", err)
	}
	if len(plan) == 0 {
		t.Error("empty plan")
	}
	if cfg.Target.Spec != "./openapi.yaml" {
		t.Errorf("caller's spec path changed to %q", cfg.Target.Spec)
	}
	// Without BaseDir the relative path resolves against the working
	// directory, where there is no openapi.yaml.
	if _, err := PlanContext(context.Background(), ScanOptions{Config: cfg}); err == nil {
		t.Error("relative spec resolved without BaseDir")
	}
	inv, err := LoadInventoryConfig(context.Background(), cfg, filepath.Dir(p), "test")
	if err != nil {
		t.Fatalf("LoadInventoryConfig: %v", err)
	}
	if len(inv.Endpoints) != 1 {
		t.Errorf("endpoints = %d", len(inv.Endpoints))
	}
}

func TestConfigObjectValidated(t *testing.T) {
	api := newMiniAPI(t)
	cfg := objectConfig(t, api)
	cfg.Scope.AcknowledgeAuthorization = false
	_, err := PlanContext(context.Background(), ScanOptions{Config: cfg, BaseDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "acknowledgeAuthorization") {
		t.Errorf("err = %v, want validation error", err)
	}
}

func TestLoadInventoryConfigOutOfScopeURL(t *testing.T) {
	api := newMiniAPI(t)
	cfg := objectConfig(t, api)
	cfg.Target.Spec = "http://evil.example.invalid/openapi.yaml?token=s3cr3t-value"
	_, err := LoadInventoryConfig(context.Background(), cfg, "", "test")
	if err == nil {
		t.Fatal("out-of-scope spec URL accepted")
	}
	if strings.Contains(err.Error(), "s3cr3t-value") {
		t.Errorf("error leaks URL secret: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "scope") {
		t.Errorf("err = %v, want out-of-scope error", err)
	}
}
