package ui

import (
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// msg is a message key; the Key field name lets TestI18nKeysComplete find
// the keys used from Go code.
type msg struct{ Key string }

// formErrors maps a form field name to the message key of its first error.
type formErrors map[string]string

func (f formErrors) add(field string, m msg) {
	if _, ok := f[field]; !ok {
		f[field] = m.Key
	}
}

// Wizard limits.
const (
	maxProfileCards = 64
	maxMatrixRows   = 128
	maxRate         = 1000
	maxConcurrency  = 64
	maxTimeoutSec   = 600
)

var (
	roles     = []string{"admin", "user", "none"}
	authTypes = []string{"bearer", "cookie", "apikey", "basic", "none"}
	// paramNameRe is an accepted owned-ID parameter name.
	paramNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	methods     = map[string]bool{"*": true, "GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
)

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// splitList splits on commas and line breaks, trims each entry and drops
// empty ones.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// withoutUserinfo returns s with any user:password@ part removed, for
// showing a rejected URL back in its field.
func withoutUserinfo(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = nil
	return u.String()
}

// --- Target ---------------------------------------------------------------

// targetForm is the submitted target step, as shown back in the form.
type targetForm struct {
	BaseURL    string
	SpecURL    string
	AllowHosts string
	Ack        bool
	SpecFile   string // the stored spec file name, if any
}

// targetInput is a valid target step ready to apply.
type targetInput struct {
	baseURL    string
	specURL    string
	allowHosts []string
	upload     *multipart.FileHeader
}

func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

// hostPort is u's host with an explicit port (the scheme default if none).
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return strings.ToLower(u.Host)
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), defaultPort(u.Scheme)))
}

// parseHTTPURL accepts an absolute http(s) URL with a host and no userinfo.
func parseHTTPURL(s string) (*url.URL, msg, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(s, " \t\r\n") {
		return nil, msg{Key: "target.err.url"}, false
	}
	if u.User != nil {
		return nil, msg{Key: "target.err.userinfo"}, false
	}
	return u, msg{}, true
}

// validHostEntry accepts "host" or "host:port" (IPv6 in brackets).
func validHostEntry(h string) bool {
	u, err := url.Parse("http://" + h)
	return err == nil && u.Host == h && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Hostname() != ""
}

// hostIn reports whether u's host:port is listed; an entry without a port
// means u's scheme default, as in the engine's scope check.
func hostIn(u *url.URL, hosts []string) bool {
	want := hostPort(u)
	for _, h := range hosts {
		hu, _ := url.Parse("http://" + h)
		if hu == nil {
			continue
		}
		hu.Scheme = u.Scheme
		if hostPort(hu) == want {
			return true
		}
	}
	return false
}

// parseTarget validates the target step. Nothing is saved here.
func parseTarget(r *http.Request, p *Project) (targetForm, targetInput, formErrors) {
	errs := formErrors{}
	f := targetForm{
		BaseURL:    strings.TrimSpace(r.PostFormValue("baseUrl")),
		SpecURL:    strings.TrimSpace(r.PostFormValue("specUrl")),
		AllowHosts: strings.TrimSpace(r.PostFormValue("allowHosts")),
		Ack:        r.PostFormValue("ack") != "",
		SpecFile:   p.SpecFile,
	}
	var in targetInput
	var base *url.URL
	if f.BaseURL == "" {
		errs.add("baseUrl", msg{Key: "target.err.base_required"})
	} else if u, m, ok := parseHTTPURL(f.BaseURL); !ok {
		errs.add("baseUrl", m)
	} else {
		base = u
		in.baseURL = strings.TrimRight(f.BaseURL, "/")
	}

	for _, h := range strings.Fields(strings.ReplaceAll(f.AllowHosts, ",", " ")) {
		if !validHostEntry(h) {
			errs.add("allowHosts", msg{Key: "target.err.host"})
			continue
		}
		in.allowHosts = append(in.allowHosts, strings.ToLower(h))
	}
	if base != nil {
		if len(in.allowHosts) == 0 && errs["allowHosts"] == "" {
			in.allowHosts = []string{hostPort(base)}
		} else if errs["allowHosts"] == "" && !hostIn(base, in.allowHosts) {
			errs.add("allowHosts", msg{Key: "target.err.host_missing"})
		}
	}

	if r.MultipartForm != nil {
		if fhs := r.MultipartForm.File["specFile"]; len(fhs) > 0 && fhs[0].Filename != "" {
			in.upload = fhs[0]
		}
	}
	switch {
	case in.upload != nil:
		if _, err := specName(filepath.Ext(in.upload.Filename)); err != nil {
			errs.add("specFile", msg{Key: "target.err.spec_ext"})
		} else if in.upload.Size > maxSpecBytes {
			errs.add("specFile", msg{Key: "target.err.spec_size"})
		}
	case f.SpecURL != "":
		u, m, ok := parseHTTPURL(f.SpecURL)
		switch {
		case !ok:
			errs.add("specUrl", m)
		case base != nil && errs["allowHosts"] == "" && !hostIn(u, in.allowHosts):
			errs.add("specUrl", msg{Key: "target.err.spec_host"})
		default:
			in.specURL = f.SpecURL
		}
	case p.SpecFile == "":
		errs.add("specFile", msg{Key: "target.err.spec_required"})
	}
	if !f.Ack {
		errs.add("ack", msg{Key: "target.err.ack"})
	}
	f.BaseURL = withoutUserinfo(f.BaseURL)
	f.SpecURL = withoutUserinfo(f.SpecURL)
	return f, in, errs
}

// --- Profiles -------------------------------------------------------------

// profileCard is one profile card as submitted (secrets excluded).
type profileCard struct {
	Index       int
	Orig        string
	Def         ProfileDef
	Identifiers string
	OwnsParam   string
	OwnsIDs     string
	secret      Secret // submitted credential fields (never rendered)
}

// parseProfiles reads the p<i>.* card fields. Blank cards and cards marked
// for removal are left out; removed lists their original names.
func parseProfiles(r *http.Request) (cards []profileCard, errs formErrors) {
	errs = formErrors{}
	form := r.PostForm
	seen := map[string]bool{}
	for i := 0; i < maxProfileCards; i++ {
		pre := fmt.Sprintf("p%d.", i)
		if !form.Has(pre + "name") {
			continue
		}
		get := func(k string) string { return strings.TrimSpace(form.Get(pre + k)) }
		if get("remove") != "" {
			continue
		}
		c := profileCard{
			Index:       i,
			Orig:        get("orig"),
			Identifiers: get("ids"),
			OwnsParam:   get("ownsParam"),
			OwnsIDs:     get("ownsIds"),
			Def: ProfileDef{
				Name:     get("name"),
				Role:     get("role"),
				AuthType: get("auth"),
				AuthName: get("authName"),
				AuthIn:   get("authIn"),
			},
		}
		if c.Def.Name == "" {
			continue // the empty card for a new profile
		}
		c.secret = Secret{Token: form.Get(pre + "token"), Username: form.Get(pre + "username"), Password: form.Get(pre + "password")}
		d := &c.Def
		switch {
		case !ValidProfileName(d.Name):
			errs.add(pre+"name", msg{Key: "profiles.err.name"})
		case seen[d.Name]:
			errs.add(pre+"name", msg{Key: "profiles.err.duplicate"})
		}
		seen[d.Name] = true
		if !oneOf(d.Role, roles) {
			errs.add(pre+"role", msg{Key: "profiles.err.role"})
		}
		if !oneOf(d.AuthType, authTypes) {
			errs.add(pre+"auth", msg{Key: "profiles.err.auth"})
		}
		if d.AuthType == "apikey" && d.AuthIn != "" && d.AuthIn != "header" && d.AuthIn != "query" {
			errs.add(pre+"authIn", msg{Key: "profiles.err.in"})
		}
		if d.AuthType != "apikey" {
			d.AuthIn = ""
		}
		if d.AuthType != "apikey" && d.AuthType != "cookie" {
			d.AuthName = ""
		}
		d.Identifiers = splitList(c.Identifiers)

		owns := map[string][]string{}
		for k := range form {
			param, ok := strings.CutPrefix(k, pre+"owns.")
			if !ok {
				continue
			}
			if ids := splitList(form.Get(k)); len(ids) > 0 && paramNameRe.MatchString(param) {
				owns[param] = ids
			}
		}
		if c.OwnsParam != "" || c.OwnsIDs != "" {
			if !paramNameRe.MatchString(c.OwnsParam) {
				errs.add(pre+"ownsParam", msg{Key: "profiles.err.owns_param"})
			} else if ids := splitList(c.OwnsIDs); len(ids) > 0 {
				owns[c.OwnsParam] = append(owns[c.OwnsParam], ids...)
			}
		}
		if len(owns) > 0 {
			d.Owns = owns
		}
		cards = append(cards, c)
	}
	return cards, errs
}

// templateProfiles is the "admin + 2 users + anonymous" set.
func templateProfiles() []ProfileDef {
	return []ProfileDef{
		{Name: "admin", Role: "admin", AuthType: "bearer"},
		{Name: "alice", Role: "user", AuthType: "bearer"},
		{Name: "bob", Role: "user", AuthType: "bearer"},
		{Name: "anonymous", Role: "none", AuthType: "none"},
	}
}

// needsSameRoleWarning reports whether no role other than "none" has two
// profiles, which BOLA checks need.
func needsSameRoleWarning(defs []ProfileDef) bool {
	if len(defs) == 0 {
		return false
	}
	n := map[string]int{}
	for _, d := range defs {
		if d.Role != "none" {
			n[d.Role]++
			if n[d.Role] >= 2 {
				return false
			}
		}
	}
	return true
}

// --- Settings -------------------------------------------------------------

// settingsForm is the submitted settings step, as shown back in the form.
type settingsForm struct {
	Rate         string
	Concurrency  string
	Timeout      string
	Destructive  bool
	Threshold    string
	IgnoreFields string
	Proxy        string
	Insecure     bool
	Matrix       []matrixRow
}

type matrixRow struct {
	Index   int
	Pattern string
	Allow   []string
}

// confirmOK reports whether the destructive-mode confirmation was typed:
// "anladım" or "I understand", case-insensitive (Turkish casing for the
// Turkish phrase, so ANLADIM counts), surrounding spaces ignored.
func confirmOK(v string) bool {
	v = strings.TrimSpace(v)
	return strings.EqualFold(v, "I understand") || strings.ToLowerSpecial(unicode.TurkishCase, v) == "anladım"
}

// validMatrixPattern accepts "/path/glob" or "METHOD /path/glob".
func validMatrixPattern(p string) bool {
	f := strings.Fields(p)
	switch len(f) {
	case 1:
		return strings.HasPrefix(f[0], "/")
	case 2:
		return methods[strings.ToUpper(f[0])] && strings.HasPrefix(f[1], "/")
	}
	return false
}

// parseSettings validates the settings step against p and, if valid,
// returns the new safety, compare and matrix values in out.
func parseSettings(r *http.Request, p *Project) (settingsForm, *Project, formErrors) {
	errs := formErrors{}
	get := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	f := settingsForm{
		Rate: get("rate"), Concurrency: get("concurrency"), Timeout: get("timeout"),
		Destructive: get("destructive") != "", Threshold: get("threshold"),
		IgnoreFields: r.PostFormValue("ignoreFields"), Proxy: get("proxy"), Insecure: get("insecure") != "",
	}
	out := *p
	out.Safety.Insecure = f.Insecure

	if v, err := strconv.ParseFloat(f.Rate, 64); err != nil || v <= 0 || v > maxRate {
		errs.add("rate", msg{Key: "settings.err.rate"})
	} else {
		out.Safety.Rate = v
	}
	if v, err := strconv.Atoi(f.Concurrency); err != nil || v < 1 || v > maxConcurrency {
		errs.add("concurrency", msg{Key: "settings.err.concurrency"})
	} else {
		out.Safety.Concurrency = v
	}
	if v, err := strconv.Atoi(f.Timeout); err != nil || v < 1 || v > maxTimeoutSec {
		errs.add("timeout", msg{Key: "settings.err.timeout"})
	} else {
		out.Safety.TimeoutSec = v
	}
	out.Threshold = 0
	if f.Threshold != "" {
		if v, err := strconv.ParseFloat(f.Threshold, 64); err != nil || v <= 0 || v > 1 {
			errs.add("threshold", msg{Key: "settings.err.threshold"})
		} else {
			out.Threshold = v
		}
	}
	out.IgnoreFields = splitList(f.IgnoreFields)
	out.Safety.Proxy = ""
	if f.Proxy != "" {
		u, err := url.Parse(f.Proxy)
		switch {
		case err != nil || u.Host == "" || !oneOf(strings.ToLower(u.Scheme), []string{"http", "https", "socks5"}):
			errs.add("proxy", msg{Key: "settings.err.proxy"})
		case u.User != nil:
			errs.add("proxy", msg{Key: "settings.err.proxy_userinfo"})
		default:
			out.Safety.Proxy = f.Proxy
		}
		f.Proxy = withoutUserinfo(f.Proxy)
	}

	switch {
	case !f.Destructive:
		out.Safety.AllowDestructive = false
	case p.Safety.AllowDestructive:
		// Already confirmed earlier; it stays on.
	case confirmOK(r.PostFormValue("confirm")):
		out.Safety.AllowDestructive = true
	default:
		errs.add("confirm", msg{Key: "settings.err.confirm"})
	}

	allowed := matrixColumns(p)
	matrix := map[string][]string{}
	for i := 0; i < maxMatrixRows; i++ {
		pre := fmt.Sprintf("m%d.", i)
		if !r.PostForm.Has(pre + "pattern") {
			continue
		}
		row := matrixRow{Index: i, Pattern: strings.Join(strings.Fields(r.PostForm.Get(pre+"pattern")), " ")}
		for _, a := range r.PostForm[pre+"allow"] {
			if oneOf(a, allowed) && !oneOf(a, row.Allow) {
				row.Allow = append(row.Allow, a)
			}
		}
		if row.Pattern == "" {
			continue
		}
		f.Matrix = append(f.Matrix, row)
		if !validMatrixPattern(row.Pattern) {
			errs.add(pre+"pattern", msg{Key: "settings.err.matrix"})
			continue
		}
		matrix[row.Pattern] = append(matrix[row.Pattern], row.Allow...)
		if matrix[row.Pattern] == nil {
			matrix[row.Pattern] = []string{}
		}
	}
	out.Matrix = nil
	if len(matrix) > 0 {
		out.Matrix = matrix
	}
	return f, &out, errs
}

// matrixColumns are the values a matrix cell may allow: the roles, owner
// and the profile names.
func matrixColumns(p *Project) []string {
	cols := []string{"admin", "user", "none", "owner"}
	var names []string
	for _, pd := range p.Profiles {
		if !oneOf(pd.Name, cols) {
			names = append(names, pd.Name)
		}
	}
	sort.Strings(names)
	return append(cols, names...)
}
