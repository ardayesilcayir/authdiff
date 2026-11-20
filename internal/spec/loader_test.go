package spec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	petstorePath = "../../test/testdata/petstore.yaml"
	fastapiPath  = "../../test/testdata/fastapi31.json"
)

func find(t *testing.T, inv *Inventory, key string) Endpoint {
	t.Helper()
	for _, e := range inv.Endpoints {
		if e.Key() == key {
			return e
		}
	}
	t.Fatalf("endpoint %q not found", key)
	return Endpoint{}
}

func TestLoadPetstore(t *testing.T) {
	inv, err := Load(context.Background(), petstorePath, nil)
	require.NoError(t, err)
	assert.Equal(t, "Petstore", inv.Title)
	assert.Equal(t, "1.0.0", inv.Version)
	assert.Equal(t, petstorePath, inv.SpecPath)

	var keys []string
	for _, e := range inv.Endpoints {
		keys = append(keys, e.Key())
	}
	assert.Equal(t, []string{
		"GET /pets", "POST /pets",
		"GET /pets/{petId}", "PUT /pets/{petId}", "DELETE /pets/{petId}",
	}, keys)

	get := find(t, inv, "GET /pets/{petId}")
	assert.Equal(t, []string{"petId"}, get.PathParams())
	assert.Equal(t, "showPetById", get.OperationID)
	assert.False(t, get.Secured)
	for _, p := range get.Params {
		if p.Required {
			assert.NotNil(t, p.Example, p.Name)
		}
	}
	assert.Equal(t, []string{"id", "name", "tag"}, get.ResponseFields)

	post := find(t, inv, "POST /pets")
	assert.True(t, post.Secured)
	require.NotNil(t, post.Body)
	assert.Equal(t, []string{"name", "tag"}, post.Body.Fields)

	del := find(t, inv, "DELETE /pets/{petId}")
	assert.Equal(t, []string{"pets", "admin"}, del.Tags)
	require.Len(t, del.Params, 2)
	assert.Equal(t, "header", del.Params[1].In)
	assert.Equal(t, "3fa85f64-5717-4562-b3fc-2c963f66afa6", del.Params[1].Example)
	assert.Greater(t, del.Line, 0)
}

func TestLoadFastAPI31(t *testing.T) {
	inv, err := Load(context.Background(), fastapiPath, nil)
	require.NoError(t, err)
	assert.Equal(t, "Vuln Lab", inv.Title)

	post := find(t, inv, "POST /orders")
	require.NotNil(t, post.Body)
	assert.Equal(t, "application/json", post.Body.ContentType)
	assert.Equal(t, []string{"coupon", "item", "note", "owner_id", "quantity"}, post.Body.Fields)
	body, ok := post.Body.Example.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "SAVE10", body["coupon"])
	assert.Equal(t, "string", body["note"])
	assert.Equal(t, 1, body["owner_id"])
	assert.Equal(t, 1, body["quantity"])
	assert.True(t, post.Secured)
	assert.Equal(t, []string{"customer", "email", "id", "item", "owner_id", "phone", "quantity"}, post.ResponseFields)
	assert.Greater(t, post.Line, 0)

	get := find(t, inv, "GET /orders/{orderId}")
	assert.True(t, get.Secured)
	assert.Equal(t, []string{"orderId"}, get.PathParams())
	require.Len(t, get.Params, 2)
	assert.Equal(t, 1, get.Params[0].Example)
	assert.False(t, get.Params[1].Required)
	assert.Equal(t, "string", get.Params[1].Example)
	assert.Greater(t, get.Line, 0)

	health := find(t, inv, "GET /health")
	assert.False(t, health.Secured)
	assert.Nil(t, health.Body)
	assert.Empty(t, health.ResponseFields)

	// ordering is by path, then method
	assert.Equal(t, "DELETE /admin/users/{userId}", inv.Endpoints[0].Key())
	assert.True(t, find(t, inv, "DELETE /admin/users/{userId}").IsAdminFunction(nil))
}

func TestLoadGlobalSecurityAndOverride(t *testing.T) {
	const doc = `openapi: 3.0.3
info: {title: g, version: "1"}
security:
  - bearer: []
paths:
  /a:
    get:
      responses: {"200": {description: ok}}
  /b:
    get:
      security: []
      responses: {"200": {description: ok}}
  /c:
    get:
      security:
        - {}
      responses: {"200": {description: ok}}
    trace:
      responses: {"200": {description: ok}}
    parameters:
      - {name: q, in: query, required: true, schema: {type: string}}
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
`
	p := filepath.Join(t.TempDir(), "g.yaml")
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))
	inv, err := Load(context.Background(), p, nil)
	require.NoError(t, err)
	a := find(t, inv, "GET /a")
	assert.True(t, a.Secured)
	assert.Equal(t, 6, a.Line)
	assert.False(t, find(t, inv, "GET /b").Secured)
	assert.False(t, find(t, inv, "GET /c").Secured)
	tr := find(t, inv, "TRACE /c")
	require.Len(t, tr.Params, 1)
	assert.Equal(t, "q", tr.Params[0].Name)
	assert.Equal(t, "GET /a", inv.Endpoints[0].Key())
	assert.Equal(t, "TRACE /c", inv.Endpoints[len(inv.Endpoints)-1].Key())
}

func TestLoadFromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing.json" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, fastapiPath)
	}))
	defer srv.Close()

	inv, err := Load(context.Background(), srv.URL+"/openapi.json", srv.Client())
	require.NoError(t, err)
	assert.Len(t, inv.Endpoints, 4)

	_, err = Load(context.Background(), srv.URL+"/openapi.json", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client")

	_, err = Load(context.Background(), srv.URL+"/missing.json", srv.Client())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestLoadErrors(t *testing.T) {
	_, err := Load(context.Background(), filepath.Join(t.TempDir(), "nope.yaml"), nil)
	require.Error(t, err)

	p := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(p, []byte("::: not [ yaml"), 0o600))
	_, err = Load(context.Background(), p, nil)
	require.Error(t, err)

	p2 := filepath.Join(t.TempDir(), "nopaths.yaml")
	require.NoError(t, os.WriteFile(p2, []byte("hello: world\n"), 0o600))
	_, err = Load(context.Background(), p2, nil)
	require.Error(t, err)
}

func TestLoadYAML31Normalization(t *testing.T) {
	const doc = `openapi: 3.1.0
info: {title: n, version: "1"}
paths:
  /n:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                a: {type: integer, exclusiveMinimum: 3}
                b: {const: fixed}
                c: {type: "null"}
                d: {oneOf: [{type: "null"}]}
      responses:
        200:
          description: ok
`
	p := filepath.Join(t.TempDir(), "n.yaml")
	require.NoError(t, os.WriteFile(p, []byte(doc), 0o600))
	inv, err := Load(context.Background(), p, nil)
	require.NoError(t, err)
	e := find(t, inv, "POST /n")
	body, ok := e.Body.Example.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 4, body["a"])
	assert.Equal(t, "fixed", body["b"])
	assert.Equal(t, []string{"a", "b", "c", "d"}, e.Body.Fields)
}
