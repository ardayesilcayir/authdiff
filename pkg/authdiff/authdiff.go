// Package authdiff is the public orchestration API of authdiff: it loads a
// config, the OpenAPI spec and the rules, runs the scan engine and applies
// the ignore baseline. The CLI is a thin layer over this package.
package authdiff

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/engine"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// Result is the outcome of a scan.
type Result = finding.Result

// Finding is one reported authorization problem.
type Finding = finding.Finding

// maxRetries is the global retry budget for network errors and 429/503.
const maxRetries = 3

// Overrides are command-line values that replace the config file's. A nil
// pointer or empty slice leaves the config value unchanged; RuleDirs are
// added to the config's rules.dirs.
type Overrides struct {
	Rate             *float64
	Concurrency      *int
	AllowDestructive *bool
	Insecure         *bool
	FailOn           *string
	Formats          []string
	OutputDir        *string
	Include          []string
	Exclude          []string
	Tags             []string
	RuleDirs         []string
}

// ScanOptions configures Scan and Plan.
type ScanOptions struct {
	ConfigPath string
	// IgnoreFile is the baseline of suppressed finding IDs; "" means none.
	// A missing file is an empty baseline.
	IgnoreFile string
	// Version is reported in the result and in the User-Agent.
	Version   string
	Overrides Overrides
	// Log receives progress and warnings; nil discards them.
	Log *slog.Logger
}

// UserAgent returns the User-Agent header authdiff sends for version.
func UserAgent(version string) string {
	if version == "" {
		version = "dev"
	}
	return "authdiff/" + version + " (+https://github.com/ardayesilcayir/authdiff)"
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// LoadConfig loads the config file (env expansion and defaults), resolves the
// spec path and rules.dirs relative to the config file's directory, applies
// o and validates the result.
func LoadConfig(path string, o Overrides) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	if s := cfg.Target.Spec; !isURL(s) && !filepath.IsAbs(s) {
		cfg.Target.Spec = filepath.Join(base, s)
	}
	for i, d := range cfg.Rules.Dirs {
		if !filepath.IsAbs(d) {
			cfg.Rules.Dirs[i] = filepath.Join(base, d)
		}
	}
	applyOverrides(cfg, o)
	if err := config.Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyOverrides(cfg *config.Config, o Overrides) {
	if o.Rate != nil {
		cfg.Safety.Rate = *o.Rate
	}
	if o.Concurrency != nil {
		cfg.Safety.Concurrency = *o.Concurrency
	}
	if o.AllowDestructive != nil {
		cfg.Safety.AllowDestructive = *o.AllowDestructive
	}
	if o.Insecure != nil {
		cfg.Safety.Insecure = *o.Insecure
	}
	if o.FailOn != nil {
		cfg.Output.FailOn = *o.FailOn
	}
	if fs := cleanList(o.Formats); len(fs) > 0 {
		cfg.Output.Formats = fs
	}
	if o.OutputDir != nil {
		cfg.Output.Dir = *o.OutputDir
	}
	if len(o.Include) > 0 {
		cfg.Filter.Include = o.Include
	}
	if len(o.Exclude) > 0 {
		cfg.Filter.Exclude = o.Exclude
	}
	if len(o.Tags) > 0 {
		cfg.Filter.Tags = o.Tags
	}
	cfg.Rules.Dirs = append(cfg.Rules.Dirs, o.RuleDirs...)
}

// cleanList trims each entry and drops empty ones.
func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// LoadRules returns the built-in rules plus every rule in dirs, minus the
// disabled IDs. A rule ID defined twice is an error naming both sources, and
// so is a disabled ID that no rule has.
func LoadRules(dirs, disable []string) ([]rules.Rule, error) {
	all, err := rules.LoadBuiltin()
	if err != nil {
		return nil, fmt.Errorf("load built-in rules: %w", err)
	}
	for _, d := range dirs {
		rs, err := rules.LoadDir(d)
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	seen := make(map[string]string, len(all))
	for _, r := range all {
		if prev, ok := seen[r.ID]; ok {
			return nil, fmt.Errorf("duplicate rule ID %s in %s and %s", r.ID, prev, r.Source)
		}
		seen[r.ID] = r.Source
	}
	off := map[string]bool{}
	for _, id := range disable {
		if _, ok := seen[id]; !ok {
			return nil, fmt.Errorf("rules.disable: unknown rule ID %q", id)
		}
		off[id] = true
	}
	out := make([]rules.Rule, 0, len(all))
	for _, r := range all {
		if !off[r.ID] {
			out = append(out, r)
		}
	}
	return out, nil
}

// newClient builds the scoped transport for cfg.
func newClient(cfg *config.Config, version string) (*transport.Client, error) {
	return transport.New(transport.Options{
		AllowHosts:       cfg.Scope.AllowHosts,
		Rate:             cfg.Safety.Rate,
		AllowDestructive: cfg.Safety.AllowDestructive,
		Timeout:          cfg.Safety.Timeout,
		MaxResponseBytes: cfg.Safety.MaxResponseBytes,
		Insecure:         cfg.Safety.Insecure,
		UserAgent:        UserAgent(version),
		Secrets:          cfg.Secrets(),
		Retries:          maxRetries,
	})
}

// loadInventory loads and filters the spec of cfg. A URL spec is downloaded
// through client (so scope and safe mode apply); client may be nil for files.
func loadInventory(ctx context.Context, cfg *config.Config, client *transport.Client) (*spec.Inventory, error) {
	var hc *http.Client
	if client != nil {
		hc = client.HTTP()
	}
	inv, err := spec.Load(ctx, cfg.Target.Spec, hc)
	if err != nil {
		return nil, err
	}
	inv = inv.Filter(cfg.Filter.Include, cfg.Filter.Exclude, cfg.Filter.Tags)
	inv.SpecPath = displaySpecPath(cfg.Target.Spec)
	return inv, nil
}

// LoadInventory loads the config at path with o applied and returns the
// filtered endpoint inventory. No request is sent except, when the spec is a
// URL, its download through the scoped transport.
func LoadInventory(ctx context.Context, path string, o Overrides, version string) (*spec.Inventory, error) {
	cfg, err := LoadConfig(path, o)
	if err != nil {
		return nil, err
	}
	var client *transport.Client
	if isURL(cfg.Target.Spec) {
		if client, err = newClient(cfg, version); err != nil {
			return nil, err
		}
	}
	return loadInventory(ctx, cfg, client)
}

// displaySpecPath is the spec location shown in reports: URLs unchanged,
// files relative to the working directory with forward slashes (the base
// name if no relative path exists).
func displaySpecPath(src string) string {
	if isURL(src) {
		return src
	}
	abs, err := filepath.Abs(src)
	if err != nil {
		return filepath.Base(src)
	}
	wd, err := os.Getwd()
	if err != nil {
		return filepath.Base(src)
	}
	rel, err := filepath.Rel(wd, abs)
	if err != nil {
		return filepath.Base(src)
	}
	return filepath.ToSlash(rel)
}

func logger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return l
}

// Scan runs a full scan as described by o. On cancellation it returns the
// partial result together with the context error, so reports can still be
// written.
func Scan(ctx context.Context, o ScanOptions) (*Result, error) {
	log := logger(o.Log)
	cfg, err := LoadConfig(o.ConfigPath, o.Overrides)
	if err != nil {
		return nil, err
	}
	rs, err := LoadRules(cfg.Rules.Dirs, cfg.Rules.Disable)
	if err != nil {
		return nil, err
	}
	baseline, err := loadBaseline(o.IgnoreFile)
	if err != nil {
		return nil, err
	}
	client, err := newClient(cfg, o.Version)
	if err != nil {
		return nil, err
	}
	inv, err := loadInventory(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	log.Info("scan starting", "target", cfg.Target.BaseURL, "endpoints", len(inv.Endpoints),
		"rules", len(rs), "profiles", len(cfg.Profiles))
	res, runErr := engine.Run(ctx, engine.RunOptions{
		Config: cfg, Inventory: inv, Rules: rs, Client: client, Log: log, Version: o.Version,
	})
	if res == nil {
		return nil, runErr
	}
	res.Target = cfg.Target.BaseURL
	res.SpecPath = inv.SpecPath
	res.Findings = baseline.Apply(res.Findings)
	log.Info("scan finished", "findings", len(res.Findings), "active", len(res.Active()),
		"requests", res.Stats.Requests, "blocked", res.Stats.Blocked, "errors", res.Stats.Errors)
	return res, runErr
}

func loadBaseline(path string) (*finding.Baseline, error) {
	if path == "" {
		return finding.LoadBaseline(os.DevNull)
	}
	b, err := finding.LoadBaseline(path)
	if err != nil {
		return nil, fmt.Errorf("ignore file: %w", err)
	}
	return b, nil
}

// Plan lists the requests Scan would send, in order, without sending any.
// Only a URL spec is downloaded (through the scoped transport).
func Plan(o ScanOptions) ([]engine.PlannedRequest, error) {
	cfg, err := LoadConfig(o.ConfigPath, o.Overrides)
	if err != nil {
		return nil, err
	}
	rs, err := LoadRules(cfg.Rules.Dirs, cfg.Rules.Disable)
	if err != nil {
		return nil, err
	}
	var client *transport.Client
	if isURL(cfg.Target.Spec) {
		if client, err = newClient(cfg, o.Version); err != nil {
			return nil, err
		}
	}
	inv, err := loadInventory(context.Background(), cfg, client)
	if err != nil {
		return nil, err
	}
	return engine.DryRun(engine.RunOptions{Config: cfg, Inventory: inv, Rules: rs, Log: logger(o.Log), Version: o.Version})
}
