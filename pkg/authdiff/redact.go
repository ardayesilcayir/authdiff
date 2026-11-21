package authdiff

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// isURL reports whether s is an http(s) URL; the scheme is case-insensitive.
func isURL(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// lowerScheme lower-cases the scheme of an http(s) URL so downstream loaders,
// which compare it case-sensitively, recognise it.
func lowerScheme(s string) string {
	if i := strings.Index(s, "://"); i > 0 && isURL(s) {
		return strings.ToLower(s[:i]) + s[i:]
	}
	return s
}

// RedactURL returns s with any userinfo removed and every query value
// replaced by "****". Values that are not http(s) URLs are returned as-is; an
// unparseable URL is replaced entirely.
func RedactURL(s string) string {
	if !isURL(s) {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "****"
	}
	u.User = nil
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		for i, kv := range parts {
			k, _, _ := strings.Cut(kv, "=")
			parts[i] = k + "=****"
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

// minURLSecret is the shortest query value treated as a secret when masking
// evidence; shorter values (v=1, format=json) would garble reports.
const minURLSecret = 8

// urlSecrets returns the credentials embedded in the target and spec URLs:
// userinfo (the password, or the user name when it stands alone) and query
// values. Unless all is set, query values shorter than minURLSecret are
// skipped.
func urlSecrets(cfg *config.Config, all bool) []string {
	var out []string
	for _, raw := range []string{cfg.Target.BaseURL, cfg.Target.Spec, cfg.Safety.Proxy} {
		if !isURL(raw) {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				out = append(out, pw)
			} else if n := u.User.Username(); n != "" {
				out = append(out, n)
			}
		}
		for _, vs := range u.Query() {
			for _, v := range vs {
				if v != "" && (all || len(v) >= minURLSecret) {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// scrubber masks URL secrets in free text such as errors and log values.
type scrubber struct{ r *strings.Replacer }

func newScrubber(cfg *config.Config) *scrubber {
	var pairs []string
	for _, raw := range []string{cfg.Target.BaseURL, cfg.Target.Spec, cfg.Safety.Proxy} {
		if isURL(raw) {
			pairs = append(pairs, raw, RedactURL(raw))
		}
	}
	for _, sec := range urlSecrets(cfg, true) {
		for _, form := range []string{sec, url.QueryEscape(sec), url.PathEscape(sec)} {
			pairs = append(pairs, form, "****")
		}
	}
	if len(pairs) == 0 {
		return &scrubber{}
	}
	return &scrubber{r: strings.NewReplacer(pairs...)}
}

func (sc *scrubber) String(s string) string {
	if sc.r == nil {
		return s
	}
	return sc.r.Replace(s)
}

// scrubbedError is an error whose message has URL secrets masked; errors.Is
// still sees the original chain (e.g. context.Canceled).
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// Err returns err with URL secrets masked in its message.
func (sc *scrubber) Err(err error) error {
	if err == nil {
		return nil
	}
	msg := sc.String(err.Error())
	if msg == err.Error() {
		return err
	}
	return &scrubbedError{msg: msg, err: err}
}

// uaTransport sets the authdiff User-Agent on requests that lack one.
type uaTransport struct {
	ua   string
	next http.RoundTripper
}

func (t *uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", t.ua)
	}
	return t.next.RoundTrip(r)
}

// specHTTP is client's scoped http.Client with the authdiff User-Agent, for
// downloading the spec.
func specHTTP(client *transport.Client, version string) *http.Client {
	hc := *client.HTTP()
	hc.Transport = &uaTransport{ua: UserAgent(version), next: hc.Transport}
	return &hc
}
