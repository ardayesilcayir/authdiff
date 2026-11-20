package spec

import (
	"math"

	"github.com/getkin/kin-openapi/openapi3"
)

// maxExampleDepth bounds schema recursion so $ref cycles terminate.
const maxExampleDepth = 8

// Example generates a representative value for a schema: an explicit example
// if present, otherwise the first enum value, otherwise a synthetic value of
// the right type. Recursive schemas are cut off at maxExampleDepth.
func Example(s *openapi3.Schema) any {
	return example(s, 0)
}

func example(s *openapi3.Schema, depth int) any {
	if s == nil || depth > maxExampleDepth {
		return nil
	}
	if s.Example != nil {
		return s.Example
	}
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}
	if len(s.AllOf) > 0 {
		return exampleAllOf(s, depth)
	}
	for _, group := range []openapi3.SchemaRefs{s.AnyOf, s.OneOf} {
		for _, ref := range group {
			if ref != nil && ref.Value != nil && !ref.Value.Type.Is("null") {
				return example(ref.Value, depth+1)
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
		return []any{example(s.Items.Value, depth+1)}
	case "object":
		return exampleObject(s, depth)
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

func exampleObject(s *openapi3.Schema, depth int) any {
	obj := map[string]any{}
	for name, ref := range s.Properties {
		if ref == nil {
			continue
		}
		obj[name] = example(ref.Value, depth+1)
	}
	return obj
}

func exampleAllOf(s *openapi3.Schema, depth int) any {
	merged := map[string]any{}
	for name, ref := range s.Properties {
		if ref != nil {
			merged[name] = example(ref.Value, depth+1)
		}
	}
	for _, ref := range s.AllOf {
		if ref == nil || ref.Value == nil {
			continue
		}
		v := example(ref.Value, depth+1)
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
