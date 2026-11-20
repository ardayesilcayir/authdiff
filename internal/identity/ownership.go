package identity

import (
	"strings"
	"sync"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/tidwall/gjson"
)

// Pool tracks the object IDs each profile owns, per parameter name. It is
// safe for concurrent use.
type Pool struct {
	mu  sync.RWMutex
	ids map[string]map[string][]string // profile -> param -> ids
}

// NewPool seeds a pool from the config's owns maps, preserving order.
func NewPool(c *config.Config) *Pool {
	p := &Pool{ids: map[string]map[string][]string{}}
	for _, name := range c.ProfileNames() {
		for param, vals := range c.Profiles[name].Owns {
			p.Add(name, param, vals...)
		}
	}
	return p
}

// Add appends ids for profile/param, skipping empties and duplicates.
func (p *Pool) Add(profile, param string, ids ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	byParam := p.ids[profile]
	if byParam == nil {
		byParam = map[string][]string{}
		p.ids[profile] = byParam
	}
	cur := byParam[param]
	for _, id := range ids {
		if id == "" || contains(cur, id) {
			continue
		}
		cur = append(cur, id)
	}
	if len(cur) > 0 {
		byParam[param] = cur
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// IDs returns a copy of the IDs owned by profile for param (nil if none).
func (p *Pool) IDs(profile, param string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	cur := p.ids[profile][param]
	if len(cur) == 0 {
		return nil
	}
	return append([]string(nil), cur...)
}

// HasAll reports whether profile owns at least one ID for every param.
func (p *Pool) HasAll(profile string, params []string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, param := range params {
		if len(p.ids[profile][param]) == 0 {
			return false
		}
	}
	return true
}

// Extract evaluates a JSONPath subset ($.a.b, $.items[*].id, $..id) against
// body and returns the scalar matches per key as strings. Keys without
// matches are omitted.
func Extract(body []byte, extract map[string]string) map[string][]string {
	out := map[string][]string{}
	if !gjson.ValidBytes(body) {
		return out
	}
	root := gjson.ParseBytes(body)
	for key, path := range extract {
		var vals []string
		collect(root, strings.TrimPrefix(path, "$"), &vals)
		if len(vals) > 0 {
			out[key] = vals
		}
	}
	return out
}

// collect resolves the remaining path (starting with "." or ".." or empty)
// against r and appends scalar results.
func collect(r gjson.Result, path string, out *[]string) {
	if strings.HasPrefix(path, "..") {
		rest := path[2:]
		name, tail := splitName(rest)
		walk(r, name, tail, out)
		return
	}
	path = strings.TrimPrefix(path, ".")
	if i := strings.Index(path, ".."); i >= 0 {
		for _, m := range flatten(r.Get(toGJSON(path[:i]))) {
			collect(m, path[i:], out)
		}
		return
	}
	if path == "" {
		emit(r, out)
		return
	}
	emit(r.Get(toGJSON(path)), out)
}

// splitName splits "id.x" / "id[*].x" into the first key and the remainder.
func splitName(s string) (string, string) {
	i := strings.IndexAny(s, ".[")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

// walk recursively finds every member called name and resolves tail on it.
func walk(r gjson.Result, name, tail string, out *[]string) {
	switch {
	case r.IsObject():
		r.ForEach(func(k, v gjson.Result) bool {
			if k.String() == name {
				if tail == "" {
					emit(v, out)
				} else {
					collect(v, tail, out)
				}
			}
			walk(v, name, tail, out)
			return true
		})
	case r.IsArray():
		r.ForEach(func(_, v gjson.Result) bool {
			walk(v, name, tail, out)
			return true
		})
	}
}

// toGJSON converts "a.b[*].c[0]" into gjson syntax "a.b.#.c.0".
func toGJSON(p string) string {
	p = strings.TrimPrefix(p, ".")
	p = strings.ReplaceAll(p, "[*]", ".#")
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '[':
			b.WriteByte('.')
		case ']':
		default:
			b.WriteByte(p[i])
		}
	}
	return strings.TrimPrefix(b.String(), ".")
}

func flatten(r gjson.Result) []gjson.Result {
	if r.IsArray() {
		return r.Array()
	}
	if !r.Exists() {
		return nil
	}
	return []gjson.Result{r}
}

func emit(r gjson.Result, out *[]string) {
	if r.IsArray() {
		for _, e := range r.Array() {
			emit(e, out)
		}
		return
	}
	switch r.Type {
	case gjson.String, gjson.Number, gjson.True, gjson.False:
		*out = append(*out, r.String())
	}
}
