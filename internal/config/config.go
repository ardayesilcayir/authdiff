// Package config loads, expands, defaults and validates authdiff.yaml.
package config

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of authdiff.yaml.
type Config struct {
	Version  int                   `yaml:"version"`
	Target   Target                `yaml:"target"`
	Scope    Scope                 `yaml:"scope"`
	Safety   Safety                `yaml:"safety"`
	Profiles map[string]Profile    `yaml:"profiles"`
	Harvest  []HarvestRule         `yaml:"harvest"`
	Matrix   map[string]MatrixRule `yaml:"matrix"`
	Compare  Compare               `yaml:"compare"`
	Output   Output                `yaml:"output"`
	Filter   Filter                `yaml:"filter"`
	Bodies   map[string]any        `yaml:"bodies"`
	Rules    RulesCfg              `yaml:"rules"`
}

// Target describes the API under test.
type Target struct {
	BaseURL string `yaml:"baseUrl"`
	Spec    string `yaml:"spec"`
}

// Scope restricts which hosts may be contacted.
type Scope struct {
	AllowHosts               []string `yaml:"allowHosts"`
	AcknowledgeAuthorization bool     `yaml:"acknowledgeAuthorization"`
}

// Safety holds request-pacing and safety limits.
type Safety struct {
	Rate             float64       `yaml:"rate"`
	Concurrency      int           `yaml:"concurrency"`
	AllowDestructive bool          `yaml:"allowDestructive"`
	Timeout          time.Duration `yaml:"timeout"`
	MaxResponseBytes int64         `yaml:"maxResponseBytes"`
	Insecure         bool          `yaml:"insecure"`
	// Proxy is an explicit proxy URL; empty means none (HTTP(S)_PROXY are
	// ignored).
	Proxy string `yaml:"proxy"`
}

// Profile is one identity used during a scan.
type Profile struct {
	Name        string              `yaml:"-"`
	Role        string              `yaml:"role"`
	Auth        Auth                `yaml:"auth"`
	Owns        map[string][]string `yaml:"owns"`
	Identifiers []string            `yaml:"identifiers"`
}

// Auth describes how a profile authenticates. Type is one of
// bearer, cookie, apikey, basic, none.
type Auth struct {
	Type     string `yaml:"type"`
	Token    string `yaml:"token"`
	Name     string `yaml:"name"`
	In       string `yaml:"in"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// HarvestRule collects identifiers from a profile's own responses.
type HarvestRule struct {
	Endpoint string            `yaml:"endpoint"`
	Extract  map[string]string `yaml:"extract"`
}

// MatrixRule is the expected authorization for an endpoint pattern.
type MatrixRule struct {
	Allow []string `yaml:"allow"`
}

// Compare tunes response comparison.
type Compare struct {
	IgnoreFields        []string `yaml:"ignoreFields"`
	SimilarityThreshold float64  `yaml:"similarityThreshold"`
}

// Output configures reporting.
type Output struct {
	Formats []string `yaml:"formats"`
	Dir     string   `yaml:"dir"`
	FailOn  string   `yaml:"failOn"`
}

// Filter selects which operations to test.
type Filter struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
	Tags    []string `yaml:"tags"`
}

// RulesCfg configures rule loading.
type RulesCfg struct {
	Dirs    []string `yaml:"dirs"`
	Disable []string `yaml:"disable"`
}

var envRe = regexp.MustCompile(`\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${env:NAME} with the environment value; an unset
// variable is an error naming the variable.
func expandEnv(data []byte) ([]byte, error) {
	var missing []string
	out := envRe.ReplaceAllFunc(data, func(m []byte) []byte {
		name := string(envRe.FindSubmatch(m)[1])
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("environment variable(s) not set: %v", missing)
	}
	return out, nil
}

// Load reads path, expands ${env:X}, decodes, applies defaults and validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse is Load without the file.
func Parse(data []byte) (*Config, error) {
	data, err := expandEnv(data)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	for name, p := range c.Profiles {
		p.Name = name
		c.Profiles[name] = p
	}
	c.ApplyDefaults()
	if err := Validate(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyDefaults fills unset fields with the documented defaults.
func (c *Config) ApplyDefaults() {
	if c.Safety.Rate == 0 {
		c.Safety.Rate = 5
	}
	if c.Safety.Concurrency == 0 {
		c.Safety.Concurrency = 4
	}
	if c.Safety.Timeout == 0 {
		c.Safety.Timeout = 10 * time.Second
	}
	if c.Safety.MaxResponseBytes == 0 {
		c.Safety.MaxResponseBytes = 5 * 1024 * 1024
	}
	if c.Compare.SimilarityThreshold == 0 {
		c.Compare.SimilarityThreshold = 0.85
	}
	if c.Output.Dir == "" {
		c.Output.Dir = "./authdiff-out"
	}
	if len(c.Output.Formats) == 0 {
		c.Output.Formats = []string{"terminal", "json"}
	}
	for name, p := range c.Profiles {
		if p.Name == "" {
			p.Name = name
			c.Profiles[name] = p
		}
	}
}

// Secrets returns every non-empty token and password for masking.
func (c *Config) Secrets() []string {
	var out []string
	for _, name := range c.ProfileNames() {
		a := c.Profiles[name].Auth
		if a.Token != "" {
			out = append(out, a.Token)
		}
		if a.Password != "" {
			out = append(out, a.Password)
		}
	}
	return out
}

// ProfileNames returns profile names in alphabetical order.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
