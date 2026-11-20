package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const maskPrefix = "****"

// alwaysMasked headers are masked even when no secret is configured.
var alwaysMasked = map[string]struct{}{
	"Authorization": {},
	"Cookie":        {},
	"Set-Cookie":    {},
	"X-Api-Key":     {}, // canonical form of X-API-Key
}

// mask keeps the last 4 characters of s; values shorter than 8 characters are
// fully hidden.
func mask(s string) string {
	r := []rune(s)
	if len(r) < 8 {
		return maskPrefix
	}
	return maskPrefix + string(r[len(r)-4:])
}

// jsonEscape returns s as it would appear inside a JSON string literal.
func jsonEscape(s string, escapeHTML bool) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return ""
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(b) < 2 {
		return ""
	}
	return string(b[1 : len(b)-1])
}

// redactor replaces configured secrets (and their URL/JSON-escaped forms).
type redactor struct {
	repl *strings.Replacer
}

func newRedactor(secrets []string) *redactor {
	type pair struct{ old, masked string }
	var pairs []pair
	seen := map[string]struct{}{}
	add := func(old, masked string) {
		if old == "" {
			return
		}
		if _, dup := seen[old]; dup {
			return
		}
		seen[old] = struct{}{}
		pairs = append(pairs, pair{old, masked})
	}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		m := mask(s)
		add(s, m)
		add(url.QueryEscape(s), m)
		add(url.PathEscape(s), m)
		for _, escapeHTML := range []bool{true, false} {
			if j := jsonEscape(s, escapeHTML); j != "" {
				add(j, m)
			}
		}
	}
	if len(pairs) == 0 {
		return &redactor{}
	}
	// Longest first: strings.Replacer tries patterns in argument order at
	// each position, so a longer secret is never partially matched by a
	// shorter one that is its prefix.
	sort.SliceStable(pairs, func(i, j int) bool { return len(pairs[i].old) > len(pairs[j].old) })
	args := make([]string, 0, len(pairs)*2)
	for _, p := range pairs {
		args = append(args, p.old, p.masked)
	}
	return &redactor{repl: strings.NewReplacer(args...)}
}

func (d *redactor) String(s string) string {
	if d.repl == nil {
		return s
	}
	return d.repl.Replace(s)
}

func (d *redactor) Headers(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	merged := make(map[string][]string, len(h))
	for _, k := range keys {
		ck := http.CanonicalHeaderKey(k)
		merged[ck] = append(merged[ck], h[k]...)
	}
	for ck, vals := range merged {
		joined := strings.Join(vals, ", ")
		if _, ok := alwaysMasked[ck]; ok {
			out[ck] = mask(joined)
			continue
		}
		out[ck] = d.String(joined)
	}
	return out
}

// Redact replaces every occurrence of each secret in s with "****" plus its
// last 4 characters ("****" alone for secrets shorter than 8 characters).
// Longer secrets are replaced first, so overlapping secrets leave no fragment.
func Redact(s string, secrets []string) string {
	return newRedactor(secrets).String(s)
}

// RedactHeaders flattens h into a map with canonical keys and ", "-joined
// values. Authorization, Cookie, Set-Cookie and X-API-Key are always masked
// as a whole; every other value has configured secrets replaced.
func RedactHeaders(h http.Header, secrets []string) map[string]string {
	return newRedactor(secrets).Headers(h)
}
