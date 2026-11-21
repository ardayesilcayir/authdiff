package spec

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestExample(t *testing.T) {
	lo := 5.0
	intMin := openapi3.NewIntegerSchema()
	intMin.Min = &lo

	withExample := openapi3.NewStringSchema()
	withExample.Example = "hello"

	obj := openapi3.NewObjectSchema()
	obj.Properties = openapi3.Schemas{
		"name": openapi3.NewStringSchema().NewRef(),
		"age":  openapi3.NewIntegerSchema().NewRef(),
	}
	obj.Required = []string{"name"}

	arr := openapi3.NewArraySchema()
	arr.Items = openapi3.NewBoolSchema().NewRef()

	enum := openapi3.NewStringSchema()
	enum.Enum = []any{"red", "green"}

	email := openapi3.NewStringSchema()
	email.Format = "email"
	uuid := openapi3.NewStringSchema()
	uuid.Format = "uuid"

	anyOf := openapi3.NewAnyOfSchema(openapi3.NewIntegerSchema(), openapi3.NewStringSchema())
	allOf := &openapi3.Schema{AllOf: openapi3.SchemaRefs{obj.NewRef()}}

	tests := []struct {
		name string
		s    *openapi3.Schema
		want any
	}{
		{"nil", nil, nil},
		{"string", openapi3.NewStringSchema(), "string"},
		{"email", email, "user@example.com"},
		{"uuid", uuid, "3fa85f64-5717-4562-b3fc-2c963f66afa6"},
		{"integer", openapi3.NewIntegerSchema(), 1},
		{"integer min", intMin, 5},
		{"number", openapi3.NewFloat64Schema(), 1.5},
		{"boolean", openapi3.NewBoolSchema(), true},
		{"enum", enum, "red"},
		{"example", withExample, "hello"},
		{"object", obj, map[string]any{"name": "string", "age": 1}},
		{"array", arr, []any{true}},
		{"anyOf", anyOf, 1},
		{"allOf", allOf, map[string]any{"name": "string", "age": 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Example(tt.s))
		})
	}
}

func TestExampleCycleTerminates(t *testing.T) {
	node := openapi3.NewObjectSchema()
	node.Properties = openapi3.Schemas{"next": &openapi3.SchemaRef{Value: node}}
	got := Example(node)
	depth := 0
	for m, ok := got.(map[string]any); ok; m, ok = m["next"].(map[string]any) {
		depth++
		if depth > 20 {
			t.Fatal("cycle not cut")
		}
	}
	assert.LessOrEqual(t, depth, maxExampleDepth+1)
}
