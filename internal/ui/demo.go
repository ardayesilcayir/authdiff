package ui

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	examplesfs "github.com/ardayesilcayir/authdiff/examples"
	"github.com/ardayesilcayir/authdiff/internal/config"
)

const (
	// DemoName is the name of the demo project.
	DemoName        = "vuln-lab-demo"
	demoSecretsFile = "demo-secrets.json"
	demoConfigFile  = "authdiff.yaml"
	demoEnvFile     = "vuln-lab.env"
)

var demoEnvRe = regexp.MustCompile(`\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}`)

// demoEnvValues parses the embedded vuln-lab.env (NAME=VALUE lines).
func demoEnvValues() (map[string]string, error) {
	b, err := examplesfs.FS.ReadFile(demoEnvFile)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out, sc.Err()
}

// demoConfig parses the embedded example config with the embedded lab
// tokens substituted for its ${env:X} placeholders, and reports for each
// profile which variable each credential field came from.
func demoConfig() (*config.Config, map[string]map[string]string, error) {
	env, err := demoEnvValues()
	if err != nil {
		return nil, nil, err
	}
	raw, err := examplesfs.FS.ReadFile(demoConfigFile)
	if err != nil {
		return nil, nil, err
	}
	var missing []string
	data := demoEnvRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		name := string(demoEnvRe.FindSubmatch(m)[1])
		v, ok := env[name]
		if !ok {
			missing = append(missing, name)
		}
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("demo: %s does not define %v", demoEnvFile, missing)
	}
	c, err := config.Parse(data)
	if err != nil {
		return nil, nil, fmt.Errorf("demo config: %w", err)
	}
	byValue := map[string]string{}
	for k, v := range env {
		byValue[v] = k
	}
	names := map[string]map[string]string{}
	for name, p := range c.Profiles {
		s := Secret{Token: p.Auth.Token, Username: p.Auth.Username, Password: p.Auth.Password}
		for _, f := range []string{"token", "username", "password"} {
			if n, ok := byValue[s.field(f)]; ok && s.field(f) != "" {
				if names[name] == nil {
					names[name] = map[string]string{}
				}
				names[name][f] = n
			}
		}
	}
	return c, names, nil
}

// demoEnvNames maps demo profile -> credential field -> the example's
// variable name (ADMIN_TOKEN...). It is empty if the embedded files are
// broken, which TestEnsureDemoMatchesExample rules out.
var demoEnvNames = sync.OnceValue(func() map[string]map[string]string {
	_, names, err := demoConfig()
	if err != nil {
		return nil
	}
	return names
})

// EnsureDemo creates the demo project from the embedded example config, or
// reuses the existing one, pointing base URL, spec and allowHosts at
// labURL. The lab's fake tokens are put into sec and written to
// demo-secrets.json (0600): the demo is the only project whose credentials
// touch the disk.
func EnsureDemo(st *Store, sec *Secrets, labURL string) (*Project, error) {
	base := strings.TrimRight(strings.TrimSpace(labURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("demo: invalid lab URL %q", labURL)
	}
	c, _, err := demoConfig()
	if err != nil {
		return nil, err
	}

	p, err := st.Get(DemoName)
	switch {
	case errors.Is(err, os.ErrNotExist):
		p = projectFromConfig(c)
	case err != nil:
		return nil, err
	case !p.Demo:
		return nil, fmt.Errorf("project %q exists and is not the demo project", DemoName)
	}
	p.BaseURL = base
	p.SpecURL = base + "/openapi.json"
	p.SpecFile = ""
	p.AllowHosts = []string{u.Host}
	if err := st.Save(p); err != nil {
		return nil, err
	}

	secrets := map[string]Secret{}
	for _, name := range c.ProfileNames() {
		a := c.Profiles[name].Auth
		s := Secret{Token: a.Token, Username: a.Username, Password: a.Password}
		if s == (Secret{}) {
			continue
		}
		secrets[name] = s
		sec.Set(DemoName, name, s)
	}
	b, err := json.MarshalIndent(secrets, "", "  ") //nolint:gosec // G117: demo-only fake lab tokens, the one allowed disk exception
	if err != nil {
		return nil, fmt.Errorf("demo secrets: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(st.Dir(DemoName), demoSecretsFile), b); err != nil {
		return nil, err
	}
	return p, nil
}

// loadDemoSecrets puts the lab tokens of the demo's demo-secrets.json into
// sec for each profile that has no entry in memory, so the demo keeps
// working after a server restart. A credential set or cleared in this
// session wins over the file. A missing file loads nothing.
func loadDemoSecrets(st *Store, sec *Secrets, p *Project) error {
	if !p.Demo {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(st.Dir(p.Name), demoSecretsFile)) //nolint:gosec // G304: fixed file name in the validated project dir
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("demo secrets: %w", err)
	}
	var secrets map[string]Secret
	if err := json.Unmarshal(b, &secrets); err != nil {
		return fmt.Errorf("demo secrets: %w", err)
	}
	for name, s := range secrets {
		sec.setIfAbsent(p.Name, name, s)
	}
	return nil
}

// projectFromConfig converts a parsed config into a demo Project without
// credentials. Output and rules settings have no UI counterpart.
func projectFromConfig(c *config.Config) *Project {
	p := &Project{
		Name:         DemoName,
		Demo:         true,
		CreatedAt:    time.Now().UTC(),
		BaseURL:      c.Target.BaseURL,
		SpecURL:      c.Target.Spec,
		AllowHosts:   cloneStrs(c.Scope.AllowHosts),
		Acknowledged: c.Scope.AcknowledgeAuthorization,
		Exclude:      cloneStrs(c.Filter.Exclude),
		Tags:         cloneStrs(c.Filter.Tags),
		Safety: SafetyDef{
			Rate:             c.Safety.Rate,
			Concurrency:      c.Safety.Concurrency,
			TimeoutSec:       int(c.Safety.Timeout / time.Second),
			AllowDestructive: c.Safety.AllowDestructive,
			Insecure:         c.Safety.Insecure,
			Proxy:            c.Safety.Proxy,
		},
		IgnoreFields: cloneStrs(c.Compare.IgnoreFields),
		Threshold:    c.Compare.SimilarityThreshold,
		Step:         "plan",
	}
	for _, name := range c.ProfileNames() {
		pr := c.Profiles[name]
		p.Profiles = append(p.Profiles, ProfileDef{
			Name: name, Role: pr.Role, AuthType: pr.Auth.Type, AuthName: pr.Auth.Name, AuthIn: pr.Auth.In,
			Owns: cloneOwns(pr.Owns), Identifiers: cloneStrs(pr.Identifiers),
		})
	}
	for _, h := range c.Harvest {
		p.Harvest = append(p.Harvest, config.HarvestRule{Endpoint: h.Endpoint, Extract: h.Extract})
	}
	if len(c.Matrix) > 0 {
		p.Matrix = make(map[string][]string, len(c.Matrix))
		for k, m := range c.Matrix {
			p.Matrix[k] = cloneStrs(m.Allow)
		}
	}
	return p
}
