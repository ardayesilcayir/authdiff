// Package planner turns spec endpoints into concrete HTTP requests, filling
// path parameters with object IDs owned by a chosen profile.
package planner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// Request is a fully built request, ready for the transport.
type Request struct {
	Endpoint    spec.Endpoint
	Method      string
	Path        string // path with parameters substituted (escaped), without base path
	URL         string
	Header      http.Header
	Body        []byte
	ContentType string
	// IDSources maps each path parameter to the profile that owns the value
	// used, or "" when the value came from an example or the default.
	IDSources map[string]string
}

// OwnedBy reports whether every path parameter value belongs to profile
// (true when there are no path parameters).
func (r Request) OwnedBy(profile string) bool {
	for _, owner := range r.IDSources {
		if owner != profile {
			return false
		}
	}
	return true
}

// Builder builds requests against a base URL.
type Builder struct {
	baseURL      string
	bodies       map[string]any
	pool         *identity.Pool
	profileNames []string
}

// NewBuilder creates a Builder. profileNames is the fallback order used to
// find another profile's ID when the requested one owns none.
func NewBuilder(baseURL string, bodies map[string]any, pool *identity.Pool, profileNames []string) *Builder {
	return &Builder{baseURL: strings.TrimRight(baseURL, "/"), bodies: bodies, pool: pool, profileNames: profileNames}
}

// Build creates the request for ep. An empty method means ep.Method.
// Path IDs come from idSource's pool, then the first other owner, then the
// parameter example, then "1". extra overrides top-level body keys.
func (b *Builder) Build(ep spec.Endpoint, method, idSource string, extra map[string]any) (Request, error) {
	if method == "" {
		method = ep.Method
	}
	method = strings.ToUpper(method)
	req := Request{Endpoint: ep, Method: method, Header: http.Header{}, IDSources: map[string]string{}}

	path := ep.Path
	for _, name := range ep.PathParams() {
		val, owner := b.pathValue(ep, name, idSource)
		req.IDSources[name] = owner
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(val))
	}
	req.Path = path

	q := url.Values{}
	for _, p := range ep.Params {
		if !p.Required {
			continue
		}
		switch p.In {
		case "query":
			q.Set(p.Name, exampleOr1(p.Example))
		case "header":
			req.Header.Set(p.Name, exampleOr1(p.Example))
		}
	}
	req.URL = b.baseURL + path
	if len(q) > 0 {
		req.URL += "?" + q.Encode()
	}

	body, err := b.body(ep, method, extra)
	if err != nil {
		return Request{}, err
	}
	if body != nil {
		req.Body = body
		req.ContentType = "application/json"
		if ep.Body != nil && ep.Body.ContentType != "" {
			req.ContentType = ep.Body.ContentType
		}
		req.Header.Set("Content-Type", req.ContentType)
	}
	return req, nil
}

func (b *Builder) pathValue(ep spec.Endpoint, name, idSource string) (val, owner string) {
	if ids := b.pool.IDs(idSource, name); len(ids) > 0 {
		return ids[0], idSource
	}
	for _, pn := range b.profileNames {
		if ids := b.pool.IDs(pn, name); len(ids) > 0 {
			return ids[0], pn
		}
	}
	for _, p := range ep.Params {
		if p.Name == name && p.In == "path" && p.Example != nil {
			return formatValue(p.Example), ""
		}
	}
	return "1", ""
}

func exampleOr1(v any) string {
	if v == nil {
		return "1"
	}
	return formatValue(v)
}

// formatValue renders an example as canonical text (integers without ".0").
func formatValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case json.Number:
		return t.String()
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(t)
	}
	if raw, err := json.Marshal(v); err == nil {
		return string(raw)
	}
	return fmt.Sprint(v)
}

// body returns nil when the request carries no body.
func (b *Builder) body(ep spec.Endpoint, method string, extra map[string]any) ([]byte, error) {
	var base any
	if v, ok := b.bodies[ep.Key()]; ok {
		base = v
	} else if ep.Body != nil {
		base = ep.Body.Example
	}
	noBodyMethod := method == http.MethodGet || method == http.MethodHead || method == http.MethodDelete
	if noBodyMethod && len(extra) == 0 {
		return nil, nil
	}
	if base == nil && len(extra) == 0 {
		return nil, nil
	}
	if obj, ok := base.(map[string]any); ok || base == nil {
		merged := make(map[string]any, len(obj)+len(extra))
		for k, v := range obj {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		base = merged
	}
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("encode body for %s: %w", ep.Key(), err)
	}
	return raw, nil
}
