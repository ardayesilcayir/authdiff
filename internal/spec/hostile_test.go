package spec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Regression: hostile specs must never panic the loader (they may load or
// return an error). Covers YAML NaN/Inf values and self-referential
// additionalProperties, both of which crashed older kin-openapi releases.
func TestLoadHostileSpecsDoNotPanic(t *testing.T) {
	cases := map[string]string{
		"nan": `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /a:
    get:
      parameters:
        - {name: q, in: query, schema: {type: number, minimum: .nan, maximum: .inf, default: -.inf}}
      responses: {"200": {description: ok}}
`,
		"inf-3.1": `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /a:
    get:
      parameters:
        - {name: q, in: query, schema: {type: number, exclusiveMinimum: .nan, multipleOf: .inf}}
      responses: {"200": {description: ok}}
`,
		"self-ref-additionalProperties": `openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /a:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Loop"}
      responses: {"200": {description: ok}}
components:
  schemas:
    Loop:
      type: object
      additionalProperties: {$ref: "#/components/schemas/Loop"}
`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "spec.yaml")
			if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("loader panicked: %v", r)
				}
			}()
			_, _ = Load(context.Background(), p, nil)
		})
	}
}
