// Package spec loads OpenAPI 3.0/3.1 documents into a flat endpoint inventory.
package spec

import (
	"regexp"
	"sort"
	"strings"
)

// Param is one operation parameter with a generated example value.
type Param struct {
	Name     string
	In       string // path | query | header | cookie
	Required bool
	Example  any
}

// Body is the request body of an operation.
type Body struct {
	ContentType string
	Example     any
	Fields      []string // sorted top-level property names
}

// Endpoint is a single method+path operation.
type Endpoint struct {
	Method         string // upper case
	Path           string
	OperationID    string
	Tags           []string
	Params         []Param
	Body           *Body
	Secured        bool
	ResponseFields []string // all property names in the 2xx JSON response schema, unique and sorted
	Line           int      // 1-based line of the path key in the spec file, 0 if unknown
}

// Inventory is the set of endpoints found in a spec.
type Inventory struct {
	Endpoints []Endpoint
	SpecPath  string
	Title     string
	Version   string
}

var pathParamRe = regexp.MustCompile(`\{([^{}/]+)\}`)

// Key returns "METHOD /path", e.g. "GET /orders/{orderId}".
func (e Endpoint) Key() string { return e.Method + " " + e.Path }

// PathParams returns the names of the {param} segments in path order.
func (e Endpoint) PathParams() []string {
	var out []string
	for _, m := range pathParamRe.FindAllStringSubmatch(e.Path, -1) {
		out = append(out, m[1])
	}
	return out
}

// IsAdminFunction reports whether the endpoint looks like an admin function:
// a path segment is "admin", a tag is "admin", or a matching matrix rule allows
// only the "admin" role. Matrix keys are glob patterns, optionally prefixed
// with a method ("GET /admin/**"); values are the allowed roles.
func (e Endpoint) IsAdminFunction(matrix map[string][]string) bool {
	for _, seg := range splitSegments(e.Path) {
		if strings.EqualFold(seg, "admin") {
			return true
		}
	}
	for _, t := range e.Tags {
		if strings.EqualFold(t, "admin") {
			return true
		}
	}
	for pattern, allow := range matrix {
		if len(allow) == 0 || !MatchEndpoint(pattern, e) {
			continue
		}
		onlyAdmin := true
		for _, r := range allow {
			if !strings.EqualFold(r, "admin") {
				onlyAdmin = false
				break
			}
		}
		if onlyAdmin {
			return true
		}
	}
	return false
}

// Filter returns a copy of the inventory restricted to endpoints that match
// at least one include pattern (all if none), match no exclude pattern
// (exclude wins), and carry at least one of the tags (any if none).
func (inv *Inventory) Filter(include, exclude, tags []string) *Inventory {
	out := &Inventory{SpecPath: inv.SpecPath, Title: inv.Title, Version: inv.Version}
	for _, e := range inv.Endpoints {
		if matchAny(exclude, e) {
			continue
		}
		if len(include) > 0 && !matchAny(include, e) {
			continue
		}
		if len(tags) > 0 && !hasAnyTag(e, tags) {
			continue
		}
		out.Endpoints = append(out.Endpoints, e)
	}
	return out
}

func matchAny(patterns []string, e Endpoint) bool {
	for _, p := range patterns {
		if MatchEndpoint(p, e) {
			return true
		}
	}
	return false
}

func hasAnyTag(e Endpoint, tags []string) bool {
	for _, want := range tags {
		for _, have := range e.Tags {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

var methodRank = map[string]int{"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}

func sortEndpoints(eps []Endpoint) {
	rank := func(m string) int {
		if r, ok := methodRank[m]; ok {
			return r
		}
		return len(methodRank)
	}
	sort.SliceStable(eps, func(i, j int) bool {
		a, b := eps[i], eps[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if ra, rb := rank(a.Method), rank(b.Method); ra != rb {
			return ra < rb
		}
		return a.Method < b.Method
	})
}
