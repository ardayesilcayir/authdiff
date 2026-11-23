// Package config loads, expands, defaults and validates authdiff.yaml.
package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of authdiff.yaml.
type Config struct {
	Version  int                   `yaml:"version,omitempty"`
	Target   Target                `yaml:"target,omitempty"`
	Scope    Scope                 `yaml:"scope,omitempty"`
	Safety   Safety                `yaml:"safety,omitempty"`
	Profiles map[string]Profile    `yaml:"profiles,omitempty"`
	Harvest  []HarvestRule         `yaml:"harvest,omitempty"`
	Matrix   map[string]MatrixRule `yaml:"matrix,omitempty"`
	Compare  Compare               `yaml:"compare,omitempty"`
	Output   Output                `yaml:"output,omitempty"`
	Filter   Filter                `yaml:"filter,omitempty"`
	Bodies   map[string]any        `yaml:"bodies,omitempty"`
	Rules    RulesCfg              `yaml:"rules,omitempty"`
}

// Target describes the API under test.
type Target struct {
	BaseURL string `yaml:"baseUrl,omitempty"`
	Spec    string `yaml:"spec,omitempty"`
}

// Scope restricts which hosts may be contacted.
type Scope struct {
	AllowHosts               []string `yaml:"allowHosts,omitempty"`
	AcknowledgeAuthorization bool     `yaml:"acknowledgeAuthorization,omitempty"`
}

// Safety holds request-pacing and safety limits.
type Safety struct {
	Rate             float64       `yaml:"rate,omitempty"`
	Concurrency      int           `yaml:"concurrency,omitempty"`
	AllowDestructive bool          `yaml:"allowDestructive,omitempty"`
	Timeout          time.Duration `yaml:"timeout,omitempty"`
	MaxResponseBytes int64         `yaml:"maxResponseBytes,omitempty"`
	Insecure         bool          `yaml:"insecure,omitempty"`
	// Proxy is an explicit proxy URL; empty means none (HTTP(S)_PROXY are
	// ignored).
	Proxy string `yaml:"proxy,omitempty"`
}

// Profile is one identity used during a scan.
type Profile struct {
	Name        string              `yaml:"-"`
	Role        string              `yaml:"role,omitempty"`
	Auth        Auth                `yaml:"auth,omitempty"`
	Owns        map[string][]string `yaml:"owns,omitempty"`
	Identifiers []string            `yaml:"identifiers,omitempty"`
}

// Auth describes how a profile authenticates. Type is one of
// bearer, cookie, apikey, basic, none.
type Auth struct {
	Type     string `yaml:"type,omitempty"`
	Token    string `yaml:"token,omitempty"`
	Name     string `yaml:"name,omitempty"`
	In       string `yaml:"in,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

// HarvestRule collects identifiers from a profile's own responses.
type HarvestRule struct {
	Endpoint string            `yaml:"endpoint,omitempty"`
	Extract  map[string]string `yaml:"extract,omitempty"`
}

// MatrixRule is the expected authorization for an endpoint pattern.
type MatrixRule struct {
	Allow []string `yaml:"allow"`
}

// Compare tunes response comparison.
type Compare struct {
	IgnoreFields        []string `yaml:"ignoreFields,omitempty"`
	SimilarityThreshold float64  `yaml:"similarityThreshold,omitempty"`
}

// Output configures reporting.
type Output struct {
	Formats []string `yaml:"formats,omitempty"`
	Dir     string   `yaml:"dir,omitempty"`
	FailOn  string   `yaml:"failOn,omitempty"`
}

// Filter selects which operations to test.
type Filter struct {
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
	Tags    []string `yaml:"tags,omitempty"`
}

// RulesCfg configures rule loading.
type RulesCfg struct {
	Dirs    []string `yaml:"dirs,omitempty"`
	Disable []string `yaml:"disable,omitempty"`
}

var envRe = regexp.MustCompile(`\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${env:NAME} with the environment value and returns the
// substituted values; an unset variable is an error naming the variable.
func expandEnv(data []byte) ([]byte, []string, error) {
	var missing, values []string
	out := envRe.ReplaceAllFunc(data, func(m []byte) []byte {
		name := string(envRe.FindSubmatch(m)[1])
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		values = append(values, v)
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("environment variable(s) not set: %v", missing)
	}
	return out, values, nil
}

// maskValue is the report mask: "****" plus the last 4 characters, or
// "****" alone for values shorter than 8 characters.
func maskValue(s string) string {
	r := []rune(s)
	if len(r) < 8 {
		return "****"
	}
	return "****" + string(r[len(r)-4:])
}

// scrubbedErr is an error whose message has expanded env values masked
// (yaml decode errors quote the offending scalar, which may be a token).
type scrubbedErr struct {
	msg string
	err error
}

func (e *scrubbedErr) Error() string { return e.msg }
func (e *scrubbedErr) Unwrap() error { return e.err }

// scrubErr masks every substituted env value in err's message, longest first.
func scrubErr(err error, values []string) error {
	if err == nil {
		return nil
	}
	vs := append([]string(nil), values...)
	sort.SliceStable(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	msg := err.Error()
	for _, v := range vs {
		if v == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, v, maskValue(v))
		// yaml.v3 quotes a scalar longer than 10 bytes as `first7...`.
		if len(v) > 10 {
			msg = strings.ReplaceAll(msg, "`"+v[:7]+"...`", "`"+maskValue(v)+"`")
		}
	}
	if msg == err.Error() {
		return err
	}
	return &scrubbedErr{msg: msg, err: err}
}

// Load reads path, expands ${env:X}, decodes, applies defaults and validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied or test-only path
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse is Load without the file. Unknown keys are errors, and error
// messages never contain the values substituted for ${env:X}.
func Parse(data []byte) (*Config, error) {
	data, values, err := expandEnv(data)
	if err != nil {
		return nil, err
	}
	c, err := decode(data)
	if err != nil {
		return nil, scrubErr(err, values)
	}
	return c, nil
}

func decode(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
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

// minUsernameSecret is the shortest basic-auth user name masked as a
// secret; shorter ones ("a", "bob") would garble every report.
const minUsernameSecret = 4

// Secrets returns every non-empty token and password for masking, plus for
// basic auth the user name (when at least 4 characters) and the base64
// "username:password" credential that appears in the Authorization header.
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
		if a.Type == "basic" && a.Username != "" {
			if len(a.Username) >= minUsernameSecret {
				out = append(out, a.Username)
			}
			out = append(out, base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Password)))
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
