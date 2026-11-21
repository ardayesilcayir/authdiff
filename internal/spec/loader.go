package spec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

// maxSpecBytes is the largest spec accepted; a larger one is an error, never
// silently truncated.
const maxSpecBytes = 10 * 1024 * 1024

// Load reads an OpenAPI 3.0 or 3.1 document (YAML or JSON) from a file path or,
// when src starts with http:// or https://, downloads it with client.
func Load(ctx context.Context, src string, client *http.Client) (*Inventory, error) {
	raw, err := readSource(ctx, src, client)
	if err != nil {
		return nil, err
	}
	norm, err := normalize(raw)
	if err != nil {
		return nil, fmt.Errorf("parse spec %s: %w", src, err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(norm)
	if err != nil {
		return nil, fmt.Errorf("load spec %s: %w", src, err)
	}
	inv := &Inventory{SpecPath: src}
	if doc.Info != nil {
		inv.Title, inv.Version = doc.Info.Title, doc.Info.Version
	}
	lines := lineIndex(raw)
	if doc.Paths != nil {
		for p, item := range doc.Paths.Map() {
			if item == nil {
				continue
			}
			inv.Endpoints = append(inv.Endpoints, pathEndpoints(doc, p, item, lines[p])...)
		}
	}
	sortEndpoints(inv.Endpoints)
	return inv, nil
}

func readSource(ctx context.Context, src string, client *http.Client) ([]byte, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		f, err := os.Open(src)
		if err != nil {
			return nil, fmt.Errorf("read spec: %w", err)
		}
		defer func() { _ = f.Close() }()
		b, err := readLimited(f)
		if err != nil {
			return nil, fmt.Errorf("read spec: %w", err)
		}
		return b, nil
	}
	if client == nil {
		return nil, errors.New("an http client is required to load a spec from a URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch spec: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch spec: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch spec %s: unexpected status %d", src, resp.StatusCode)
	}
	b, err := readLimited(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetch spec: %w", err)
	}
	return b, nil
}

// readLimited reads r, failing when it holds more than maxSpecBytes.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSpecBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSpecBytes {
		return nil, fmt.Errorf("spec larger than %d bytes", maxSpecBytes)
	}
	return b, nil
}

// lineIndex maps each path-like key ("/...") to the 1-based line where it
// first appears as a YAML or JSON mapping key, in a single pass.
func lineIndex(raw []byte) map[string]int {
	idx := map[string]int{}
	for i, l := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(l)
		t = strings.TrimSpace(strings.TrimPrefix(t, "{")) // single-line JSON objects
		key := lineKey(t)
		if !strings.HasPrefix(key, "/") {
			continue
		}
		if _, seen := idx[key]; !seen {
			idx[key] = i + 1
		}
	}
	return idx
}

// lineKey returns the mapping key a trimmed line starts with: a quoted
// string, or the text before ": " or a trailing ":"; "" otherwise.
func lineKey(t string) string {
	if t == "" {
		return ""
	}
	if q := t[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(t[1:], q); end >= 0 {
			return t[1 : end+1]
		}
		return ""
	}
	if i := strings.Index(t, ": "); i > 0 {
		return t[:i]
	}
	if strings.HasSuffix(t, ":") {
		return t[:len(t)-1]
	}
	return ""
}

func pathEndpoints(doc *openapi3.T, p string, item *openapi3.PathItem, line int) []Endpoint {
	var out []Endpoint
	for method, op := range item.Operations() {
		if op == nil {
			continue
		}
		g := newExampler() // one node budget per endpoint
		e := Endpoint{
			Method:      strings.ToUpper(method),
			Path:        p,
			OperationID: op.OperationID,
			Tags:        op.Tags,
			Params:      collectParams(item.Parameters, op.Parameters, g),
			Secured:     isSecured(doc, op),
			Line:        line,
		}
		e.Body = collectBody(op, g)
		e.ResponseFields = responseFields(op)
		out = append(out, e)
	}
	return out
}

func collectParams(pathLevel, opLevel openapi3.Parameters, g *exampler) []Param {
	var out []Param
	idx := map[string]int{}
	add := func(ps openapi3.Parameters) {
		for _, ref := range ps {
			if ref == nil || ref.Value == nil {
				continue
			}
			v := ref.Value
			p := Param{Name: v.Name, In: v.In, Required: v.Required || v.In == "path", Example: paramExample(v, g)}
			k := v.In + ":" + v.Name
			if i, ok := idx[k]; ok {
				out[i] = p
				continue
			}
			idx[k] = len(out)
			out = append(out, p)
		}
	}
	add(pathLevel)
	add(opLevel)
	return out
}

func paramExample(p *openapi3.Parameter, g *exampler) any {
	if p.Example != nil {
		return p.Example
	}
	if p.Schema != nil {
		return g.example(p.Schema.Value, 0)
	}
	for _, mt := range p.Content {
		if mt != nil && mt.Schema != nil {
			return g.example(mt.Schema.Value, 0)
		}
	}
	return nil
}

func collectBody(op *openapi3.Operation, g *exampler) *Body {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	content := op.RequestBody.Value.Content
	if len(content) == 0 {
		return nil
	}
	types := make([]string, 0, len(content))
	for ct := range content {
		types = append(types, ct)
	}
	sort.Strings(types)
	chosen := types[0]
	for _, ct := range types {
		if ct == "application/json" {
			chosen = ct
			break
		}
		if strings.Contains(ct, "json") && !strings.Contains(chosen, "json") {
			chosen = ct
		}
	}
	b := &Body{ContentType: chosen}
	mt := content[chosen]
	if mt == nil {
		return b
	}
	if mt.Example != nil {
		b.Example = mt.Example
	}
	if mt.Schema != nil && mt.Schema.Value != nil {
		if b.Example == nil {
			b.Example = g.example(mt.Schema.Value, 0)
		}
		b.Fields = topLevelFields(mt.Schema.Value)
	}
	return b
}

func topLevelFields(s *openapi3.Schema) []string {
	set := map[string]struct{}{}
	seen := map[*openapi3.Schema]bool{}
	budget := maxExampleNodes
	var walk func(*openapi3.Schema, int)
	walk = func(s *openapi3.Schema, depth int) {
		if s == nil || depth > maxExampleDepth || seen[s] || budget <= 0 {
			return
		}
		seen[s] = true
		budget--
		for name := range s.Properties {
			set[name] = struct{}{}
		}
		for _, group := range []openapi3.SchemaRefs{s.AllOf, s.AnyOf, s.OneOf} {
			for _, r := range group {
				if r != nil {
					walk(r.Value, depth+1)
				}
			}
		}
	}
	walk(s, 0)
	return sortedKeys(set)
}

func responseFields(op *openapi3.Operation) []string {
	if op.Responses == nil {
		return nil
	}
	set := map[string]struct{}{}
	for code, ref := range op.Responses.Map() {
		if len(code) != 3 || code[0] != '2' || ref == nil || ref.Value == nil {
			continue
		}
		for ct, mt := range ref.Value.Content {
			if mt == nil || mt.Schema == nil || !strings.Contains(ct, "json") {
				continue
			}
			collectAllFields(mt.Schema.Value, set, map[*openapi3.Schema]bool{})
		}
	}
	return sortedKeys(set)
}

func collectAllFields(s *openapi3.Schema, set map[string]struct{}, seen map[*openapi3.Schema]bool) {
	if s == nil || seen[s] {
		return
	}
	seen[s] = true
	for name, ref := range s.Properties {
		set[name] = struct{}{}
		if ref != nil {
			collectAllFields(ref.Value, set, seen)
		}
	}
	if s.Items != nil {
		collectAllFields(s.Items.Value, set, seen)
	}
	if s.AdditionalProperties.Schema != nil {
		collectAllFields(s.AdditionalProperties.Schema.Value, set, seen)
	}
	for _, group := range []openapi3.SchemaRefs{s.AllOf, s.AnyOf, s.OneOf} {
		for _, r := range group {
			if r != nil {
				collectAllFields(r.Value, set, seen)
			}
		}
	}
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isSecured reports whether the operation (or, absent an operation-level
// override, the document) declares at least one non-empty security requirement.
func isSecured(doc *openapi3.T, op *openapi3.Operation) bool {
	reqs := doc.Security
	if op.Security != nil {
		reqs = *op.Security
	}
	for _, r := range reqs {
		if len(r) > 0 {
			return true
		}
	}
	return false
}

// normalize parses a JSON or YAML document and rewrites OpenAPI 3.1 constructs
// that kin-openapi's 3.0 model cannot represent, returning 3.0-compatible JSON.
func normalize(raw []byte) ([]byte, error) {
	var generic any
	if t := strings.TrimSpace(string(raw)); strings.HasPrefix(t, "{") {
		if err := json.Unmarshal(raw, &generic); err != nil {
			return nil, err
		}
	} else if err := yaml.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	root, ok := stringifyKeys(generic).(map[string]any)
	if !ok {
		return nil, errors.New("document is not an object")
	}
	if _, ok := root["openapi"].(string); !ok {
		return nil, errors.New(`missing "openapi" version field`)
	}
	if _, ok := root["paths"]; !ok {
		return nil, errors.New(`missing "paths" section`)
	}
	if v, _ := root["openapi"].(string); strings.HasPrefix(v, "3.1") {
		root["openapi"] = "3.0.3"
	}
	normalizeNode(root)
	return json.Marshal(root)
}

// stringifyKeys converts YAML maps with non-string keys (e.g. bare 200:) to
// map[string]any so the tree is JSON-marshalable.
func stringifyKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = stringifyKeys(val)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[fmt.Sprint(k)] = stringifyKeys(val)
		}
		return m
	case []any:
		for i, val := range t {
			t[i] = stringifyKeys(val)
		}
		return t
	}
	return v
}

func normalizeNode(v any) {
	switch t := v.(type) {
	case map[string]any:
		normalizeMap(t)
		for _, child := range t {
			normalizeNode(child)
		}
	case []any:
		for _, child := range t {
			normalizeNode(child)
		}
	}
}

func normalizeMap(m map[string]any) {
	switch ty := m["type"].(type) {
	case []any:
		var rest []any
		nullable := false
		for _, x := range ty {
			if s, ok := x.(string); ok && s == "null" {
				nullable = true
				continue
			}
			rest = append(rest, x)
		}
		if nullable {
			m["nullable"] = true
		}
		if len(rest) == 0 {
			delete(m, "type")
		} else {
			m["type"] = rest[0]
		}
	case string:
		if ty == "null" {
			delete(m, "type")
			m["nullable"] = true
		}
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		list, ok := m[key].([]any)
		if !ok {
			continue
		}
		var rest []any
		for _, br := range list {
			if isNullSchema(br) {
				m["nullable"] = true
				continue
			}
			rest = append(rest, br)
		}
		if len(rest) == 0 {
			delete(m, key)
		} else if len(rest) != len(list) {
			m[key] = rest
		}
	}
	if ex, ok := m["examples"].([]any); ok {
		if _, has := m["example"]; !has && len(ex) > 0 {
			m["example"] = ex[0]
		}
		delete(m, "examples")
	}
	if c, ok := m["const"]; ok {
		if _, has := m["enum"]; !has {
			m["enum"] = []any{c}
		}
		delete(m, "const")
	}
	// 3.1 numeric exclusive bounds -> 3.0 boolean flags.
	for _, b := range [][2]string{{"exclusiveMinimum", "minimum"}, {"exclusiveMaximum", "maximum"}} {
		if n, ok := toNumber(m[b[0]]); ok {
			m[b[1]] = n
			m[b[0]] = true
		}
	}
}

func isNullSchema(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	t, ok := m["type"].(string)
	if !ok || t != "null" {
		return false
	}
	_, hasRef := m["$ref"]
	return !hasRef
}

func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
