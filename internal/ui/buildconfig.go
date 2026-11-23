package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

// ErrMissingSecrets is returned by BuildConfig when profiles lack a
// credential in memory and in the environment.
type ErrMissingSecrets struct {
	Profiles []string
}

func (e ErrMissingSecrets) Error() string {
	return "missing credentials for profile(s): " + strings.Join(e.Profiles, ", ")
}

// BuildConfig turns p into the config a scan runs with: credentials from
// sec (or the environment) filled in, defaults applied and validated. An
// uploaded spec resolves to projectDir/SpecFile. The result holds real
// secrets and must never be written to disk.
func BuildConfig(p *Project, sec *Secrets, projectDir string) (*config.Config, error) {
	if err := checkBuildable(p); err != nil {
		return nil, err
	}
	c := baseConfig(p)
	if p.SpecFile != "" {
		c.Target.Spec = p.SpecFile
		if projectDir != "" {
			c.Target.Spec = filepath.Join(projectDir, p.SpecFile)
		}
	}
	var missing []string
	for _, pd := range p.Profiles {
		s, miss := sec.resolve(p, pd)
		if miss {
			missing = append(missing, pd.Name)
		}
		prof := c.Profiles[pd.Name]
		s.applyTo(&prof.Auth)
		c.Profiles[pd.Name] = prof
	}
	if len(missing) > 0 {
		return nil, ErrMissingSecrets{Profiles: missing}
	}
	return finish(c)
}

// PlaceholderConfig is the config written to authdiff.yaml: every
// credential is a ${env:NAME} placeholder (EnvName, or the example's names
// for the demo project) and an uploaded spec is the relative SpecFile.
func PlaceholderConfig(p *Project) (*config.Config, error) {
	if err := checkBuildable(p); err != nil {
		return nil, err
	}
	c := baseConfig(p)
	if p.SpecFile != "" {
		c.Target.Spec = p.SpecFile
	}
	for _, pd := range p.Profiles {
		var s Secret
		for _, f := range secretFields(pd.AuthType) {
			s.setField(f, "${env:"+envNameFor(p, pd.Name, f)+"}")
		}
		prof := c.Profiles[pd.Name]
		s.applyTo(&prof.Auth)
		c.Profiles[pd.Name] = prof
	}
	return finish(c)
}

// checkBuildable rejects colliding profile names and a SpecFile outside
// the allowed names before any config is built from p.
func checkBuildable(p *Project) error {
	if err := ValidateProfileNames(p); err != nil {
		return err
	}
	return checkSpecFile(p.SpecFile)
}

// envVars lists, in profile order and without repeats, the environment
// variables p's PlaceholderConfig refers to.
func envVars(p *Project) []string {
	var out []string
	seen := map[string]bool{}
	for _, pd := range p.Profiles {
		for _, f := range secretFields(pd.AuthType) {
			if n := envNameFor(p, pd.Name, f); !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

func finish(c *config.Config) (*config.Config, error) {
	c.ApplyDefaults()
	if err := config.Validate(c); err != nil {
		return nil, fmt.Errorf("invalid project settings: %w", err)
	}
	return c, nil
}

// applyTo copies the credential fields into a.
func (sec Secret) applyTo(a *config.Auth) {
	a.Token, a.Username, a.Password = sec.Token, sec.Username, sec.Password
}

// baseConfig maps p to a config without credentials. Rules are never set:
// the UI runs with the built-in rules only.
func baseConfig(p *Project) *config.Config {
	c := &config.Config{
		Version: 1,
		Target:  config.Target{BaseURL: p.BaseURL, Spec: p.SpecURL},
		Scope:   config.Scope{AllowHosts: cloneStrs(p.AllowHosts), AcknowledgeAuthorization: p.Acknowledged},
		Safety: config.Safety{
			Rate:             p.Safety.Rate,
			Concurrency:      p.Safety.Concurrency,
			AllowDestructive: p.Safety.AllowDestructive,
			Timeout:          time.Duration(p.Safety.TimeoutSec) * time.Second,
			Insecure:         p.Safety.Insecure,
			Proxy:            p.Safety.Proxy,
		},
		Compare: config.Compare{IgnoreFields: cloneStrs(p.IgnoreFields), SimilarityThreshold: p.Threshold},
		Filter:  config.Filter{Exclude: cloneStrs(p.Exclude), Tags: cloneStrs(p.Tags)},
	}
	if len(p.Profiles) > 0 {
		c.Profiles = make(map[string]config.Profile, len(p.Profiles))
		for _, pd := range p.Profiles {
			c.Profiles[pd.Name] = config.Profile{
				Name:        pd.Name,
				Role:        pd.Role,
				Auth:        config.Auth{Type: pd.AuthType, Name: pd.AuthName, In: pd.AuthIn},
				Owns:        cloneOwns(pd.Owns),
				Identifiers: cloneStrs(pd.Identifiers),
			}
		}
	}
	for _, h := range p.Harvest {
		var ex map[string]string
		if h.Extract != nil {
			ex = make(map[string]string, len(h.Extract))
			for k, v := range h.Extract {
				ex[k] = v
			}
		}
		c.Harvest = append(c.Harvest, config.HarvestRule{Endpoint: h.Endpoint, Extract: ex})
	}
	if len(p.Matrix) > 0 {
		c.Matrix = make(map[string]config.MatrixRule, len(p.Matrix))
		for k, allow := range p.Matrix {
			c.Matrix[k] = config.MatrixRule{Allow: cloneStrs(allow)}
		}
	}
	return c
}

func cloneStrs(s []string) []string {
	if s == nil {
		return nil
	}
	return append(make([]string, 0, len(s)), s...)
}

func cloneOwns(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = cloneStrs(v)
	}
	return out
}
