package spec

import (
	"math"
	"sort"

	"github.com/getkin/kin-openapi/openapi3"
)

// maxExampleDepth bounds schema recursion so $ref cycles terminate.
const maxExampleDepth = 8

// maxExampleNodes is the schema-node budget of one exampler (one endpoint):
// a hostile spec whose $refs fan out cannot make generation explode.
const maxExampleNodes = 10000

// exampler generates examples with a shared node budget and a memo per
// schema, so a schema referenced many times is generated once.
type exampler struct {
	budget int
	memo   map[*openapi3.Schema]any
}

func newExampler() *exampler {
	return &exampler{budget: maxExampleNodes, memo: map[*openapi3.Schema]any{}}
}

// Example generates a representative value for a schema: an explicit example
// if present, otherwise the first enum value, otherwise a synthetic value of
// the right type. Recursive schemas are cut off at maxExampleDepth, and at
// most maxExampleNodes schema nodes are visited.
func Example(s *openapi3.Schema) any {
	return newExampler().example(s, 0)
}

func (g *exampler) example(s *openapi3.Schema, depth int) any {
	if s == nil || depth > maxExampleDepth || g.budget <= 0 {
		return nil
	}
	if v, ok := g.memo[s]; ok {
		return v
	}
	g.budget--
	v := g.generate(s, depth)
	g.memo[s] = v
	return v
}

func (g *exampler) generate(s *openapi3.Schema, depth int) any {
	if s.Example != nil {
		return s.Example
	}
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}
	if len(s.AllOf) > 0 {
		return g.exampleAllOf(s, depth)
	}
	for _, group := range []openapi3.SchemaRefs{s.AnyOf, s.OneOf} {
		for _, ref := range group {
			if ref != nil && ref.Value != nil && !ref.Value.Type.Is("null") {
				return g.example(ref.Value, depth+1)
			}
		}
	}
	switch schemaType(s) {
	case "string":
		return exampleString(s.Format)
	case "integer":
		return exampleInteger(s)
	case "number":
		if s.Min != nil {
			return *s.Min
		}
		return 1.5
	case "boolean":
		return true
	case "array":
		if s.Items == nil || s.Items.Value == nil {
			return []any{}
		}
		return []any{g.example(s.Items.Value, depth+1)}
	case "object":
		return g.exampleObject(s, depth)
	}
	return nil
}

// schemaType returns the first non-null declared type, inferring "object" or
// "array" from structure when no type is given.
func schemaType(s *openapi3.Schema) string {
	if s.Type != nil {
		for _, t := range s.Type.Slice() {
			if t != "null" {
				return t
			}
		}
	}
	switch {
	case len(s.Properties) > 0:
		return "object"
	case s.Items != nil:
		return "array"
	}
	return ""
}

func (g *exampler) exampleObject(s *openapi3.Schema, depth int) any {
	obj := map[string]any{}
	for _, name := range sortedNames(s.Properties) {
		if ref := s.Properties[name]; ref != nil {
			obj[name] = g.example(ref.Value, depth+1)
		}
	}
	return obj
}

// sortedNames returns the property names in order, so the budget is spent
// deterministically.
func sortedNames(props openapi3.Schemas) []string {
	out := make([]string, 0, len(props))
	for n := range props {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (g *exampler) exampleAllOf(s *openapi3.Schema, depth int) any {
	merged := map[string]any{}
	for _, name := range sortedNames(s.Properties) {
		if ref := s.Properties[name]; ref != nil {
			merged[name] = g.example(ref.Value, depth+1)
		}
	}
	for _, ref := range s.AllOf {
		if ref == nil || ref.Value == nil {
			continue
		}
		v := g.example(ref.Value, depth+1)
		m, ok := v.(map[string]any)
		if !ok {
			if len(merged) == 0 {
				return v
			}
			continue
		}
		for k, val := range m {
			merged[k] = val
		}
	}
	return merged
}

func exampleString(format string) string {
	switch format {
	case "email":
		return "user@example.com"
	case "uuid":
		return "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	case "date":
		return "2024-01-01"
	case "date-time":
		return "2024-01-01T00:00:00Z"
	case "uri", "url":
		return "https://example.com"
	}
	return "string"
}

func exampleInteger(s *openapi3.Schema) int {
	if s.Min == nil {
		return 1
	}
	v := int(math.Ceil(*s.Min))
	if s.ExclusiveMin && float64(v) == *s.Min {
		v++
	}
	return v
}
