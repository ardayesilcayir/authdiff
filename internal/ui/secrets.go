package ui

import (
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// Secret holds a profile's credentials. It lives only in memory (and, for
// the demo project, in demo-secrets.json).
type Secret struct {
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Secrets is the server's in-memory credential store, keyed by project and
// profile. The zero value is ready to use and safe for concurrent use.
type Secrets struct {
	mu sync.Mutex
	m  map[string]map[string]Secret
}

// NewSecrets returns an empty Secrets.
func NewSecrets() *Secrets { return &Secrets{} }

// Set replaces the credentials of project/profile.
func (s *Secrets) Set(project, profile string, sec Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]map[string]Secret{}
	}
	if s.m[project] == nil {
		s.m[project] = map[string]Secret{}
	}
	s.m[project][profile] = sec
}

// setIfAbsent sets project/profile's credentials unless memory already
// holds an entry for it (even an empty one).
func (s *Secrets) setIfAbsent(project, profile string, sec Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[project][profile]; ok {
		return
	}
	if s.m == nil {
		s.m = map[string]map[string]Secret{}
	}
	if s.m[project] == nil {
		s.m[project] = map[string]Secret{}
	}
	s.m[project][profile] = sec
}

// Get returns the credentials of project/profile held in memory.
func (s *Secrets) Get(project, profile string) (Secret, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.m[project][profile]
	return sec, ok
}

// Masked returns the stored fields of project/profile ("token", "username",
// "password") masked as "•••• " plus the last 4 characters, or "••••" for
// values shorter than 8 characters. Empty fields are left out.
func (s *Secrets) Masked(project, profile string) map[string]string {
	sec, _ := s.Get(project, profile)
	out := map[string]string{}
	for field, v := range map[string]string{"token": sec.Token, "username": sec.Username, "password": sec.Password} {
		if v != "" {
			out[field] = mask(v)
		}
	}
	return out
}

func mask(v string) string {
	r := []rune(v)
	if len(r) < 8 {
		return "••••"
	}
	return "•••• " + string(r[len(r)-4:])
}

// secretFields are the Secret fields an auth type needs.
func secretFields(authType string) []string {
	switch authType {
	case "bearer", "cookie", "apikey":
		return []string{"token"}
	case "basic":
		return []string{"username", "password"}
	}
	return nil
}

func (sec Secret) field(f string) string {
	switch f {
	case "token":
		return sec.Token
	case "username":
		return sec.Username
	case "password":
		return sec.Password
	}
	return ""
}

func (sec *Secret) setField(f, v string) {
	switch f {
	case "token":
		sec.Token = v
	case "username":
		sec.Username = v
	case "password":
		sec.Password = v
	}
}

// resolve returns profile's credentials: each field from memory, else from
// its environment variable. missing reports whether a needed field is
// empty in both.
func (s *Secrets) resolve(p *Project, pd ProfileDef) (sec Secret, missing bool) {
	mem, _ := s.Get(p.Name, pd.Name)
	for _, f := range secretFields(pd.AuthType) {
		v := mem.field(f)
		if v == "" {
			v = os.Getenv(envNameFor(p, pd.Name, f))
		}
		if v == "" {
			missing = true
		}
		sec.setField(f, v)
	}
	return sec, missing
}

// Missing returns, in profile order, the profiles of p whose auth type needs
// a credential that is neither in memory nor in its environment variable.
func (s *Secrets) Missing(p *Project) []string {
	var out []string
	for _, pd := range p.Profiles {
		if _, miss := s.resolve(p, pd); miss {
			out = append(out, pd.Name)
		}
	}
	return out
}

var envUnsafe = regexp.MustCompile(`[^A-Z0-9]`)

// EnvName is the environment variable holding a profile's credential field
// (token, username, password): AUTHDIFF_<PROFILE>_<FIELD>, the profile name
// upper-cased with every character outside A-Z0-9 replaced by '_'.
func EnvName(profile, field string) string {
	return "AUTHDIFF_" + envUnsafe.ReplaceAllString(strings.ToUpper(profile), "_") + "_" + strings.ToUpper(field)
}

// envNameFor is EnvName, except that the demo project keeps the variable
// names of the example config (ADMIN_TOKEN...).
func envNameFor(p *Project, profile, field string) string {
	if p.Demo {
		if n := demoEnvNames()[profile][field]; n != "" {
			return n
		}
	}
	return EnvName(profile, field)
}

func isWindows() bool { return runtime.GOOS == "windows" }
