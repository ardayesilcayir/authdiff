package ui

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

// Project is the UI's source of truth for one project, stored as
// project.json. It holds the wizard state, half-finished settings included,
// and never a token, user name or password: those live in Secrets.
type Project struct {
	Name         string               `json:"name"`
	Demo         bool                 `json:"demo,omitempty"`
	CreatedAt    time.Time            `json:"createdAt"`
	UpdatedAt    time.Time            `json:"updatedAt"`
	BaseURL      string               `json:"baseUrl,omitempty"`
	SpecURL      string               `json:"specUrl,omitempty"`
	SpecFile     string               `json:"specFile,omitempty"` // file name inside the project directory
	AllowHosts   []string             `json:"allowHosts,omitempty"`
	Acknowledged bool                 `json:"acknowledged,omitempty"`
	Exclude      []string             `json:"exclude,omitempty"` // "METHOD /path"
	Tags         []string             `json:"tags,omitempty"`
	Profiles     []ProfileDef         `json:"profiles,omitempty"`
	Harvest      []config.HarvestRule `json:"harvest,omitempty"`
	Safety       SafetyDef            `json:"safety"`
	Matrix       map[string][]string  `json:"matrix,omitempty"`
	IgnoreFields []string             `json:"ignoreFields,omitempty"`
	Threshold    float64              `json:"threshold,omitempty"`
	Step         string               `json:"step,omitempty"` // wizard step the user stopped at
}

// ProfileDef is a profile without its secrets.
type ProfileDef struct {
	Name        string              `json:"name"`
	Role        string              `json:"role,omitempty"`
	AuthType    string              `json:"authType,omitempty"`
	AuthName    string              `json:"authName,omitempty"`
	AuthIn      string              `json:"authIn,omitempty"`
	Owns        map[string][]string `json:"owns,omitempty"`
	Identifiers []string            `json:"identifiers,omitempty"`
}

// SafetyDef is the project's request pacing and safety settings.
type SafetyDef struct {
	Rate             float64 `json:"rate,omitempty"`
	Concurrency      int     `json:"concurrency,omitempty"`
	TimeoutSec       int     `json:"timeoutSec,omitempty"`
	AllowDestructive bool    `json:"allowDestructive,omitempty"`
	Insecure         bool    `json:"insecure,omitempty"`
	Proxy            string  `json:"proxy,omitempty"`
}

var profileNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidProfileName reports whether s is an allowed profile name: a
// lower-case letter followed by up to 31 lower-case letters, digits or '-'.
func ValidProfileName(s string) bool { return profileNameRe.MatchString(s) }

// ValidateProfileNames rejects duplicate profile names and profiles whose
// credential environment variables collide (a-b and a_b both map to
// AUTHDIFF_A_B_*), which would silently share credentials. The error names
// both profiles.
func ValidateProfileNames(p *Project) error {
	owner := map[string]string{} // env var -> profile
	seen := map[string]bool{}
	for _, pd := range p.Profiles {
		if seen[pd.Name] {
			return fmt.Errorf("profile %q is defined twice", pd.Name)
		}
		seen[pd.Name] = true
		for _, f := range []string{"token", "username", "password"} {
			n := envNameFor(p, pd.Name, f)
			if other, ok := owner[n]; ok && other != pd.Name {
				return fmt.Errorf("profiles %q and %q both use environment variable %s; rename one", other, pd.Name, n)
			}
			owner[n] = pd.Name
		}
	}
	return nil
}

// checkSpecFile allows only the names SaveSpec writes, so a SpecFile never
// points outside the project directory or at another project file.
func checkSpecFile(name string) error {
	switch name {
	case "", "spec.yaml", "spec.json":
		return nil
	}
	return fmt.Errorf("invalid specFile %q (want spec.yaml or spec.json)", name)
}

// checkProxy rejects a proxy URL carrying user info, which would put a
// credential into project.json and exports. The URL is never quoted.
func checkProxy(proxy string) error {
	if proxy == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(proxy))
	if err != nil {
		return errors.New("safety.proxy is not a valid URL")
	}
	if u.User != nil {
		return errors.New("safety.proxy must not contain credentials (user:password@)")
	}
	return nil
}

// checkStored validates the fields of p that must hold before p is
// written to or read from disk.
func checkStored(p *Project) error {
	if err := checkSpecFile(p.SpecFile); err != nil {
		return err
	}
	return checkProxy(p.Safety.Proxy)
}
