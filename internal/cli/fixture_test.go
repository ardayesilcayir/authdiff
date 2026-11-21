package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	aliceToken = "alice-secret-token-1111"
	bobToken   = "bob-secret-token-2222"
)

const miniSpec = `openapi: 3.0.3
info: { title: mini, version: "1" }
components:
  securitySchemes:
    bearer: { type: http, scheme: bearer }
security: [ { bearer: [] } ]
paths:
  /orders/{orderId}:
    get:
      operationId: getOrder
      tags: [orders]
      parameters:
        - { name: orderId, in: path, required: true, schema: { type: string } }
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: { type: string }
                  owner: { type: string }
                  total: { type: number }
`

// miniAPI serves /orders/{id} to any authenticated user (a BOLA bug) and
// counts every request it receives.
type miniAPI struct {
	*httptest.Server
	hits atomic.Int64
}

func newMiniAPI(t *testing.T) *miniAPI {
	t.Helper()
	orders := map[string]map[string]any{
		"101": {"id": "101", "owner": "alice@example.com", "total": 10},
		"201": {"id": "201", "owner": "bob@example.com", "total": 20},
	}
	api := &miniAPI{}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+aliceToken && auth != "Bearer "+bobToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"login required"}`))
			return
		}
		o, ok := orders[strings.TrimPrefix(r.URL.Path, "/orders/")]
		if !ok || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(o)
	}))
	t.Cleanup(api.Close)
	return api
}

func (a *miniAPI) host() string { return strings.TrimPrefix(a.URL, "http://") }

// writeProject writes openapi.yaml and authdiff.yaml into a temp dir and
// returns the config path. extra is appended verbatim to the config.
func writeProject(t *testing.T, api *miniAPI, extra string) string {
	t.Helper()
	t.Setenv("AD_TEST_ALICE", aliceToken)
	t.Setenv("AD_TEST_BOB", bobToken)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openapi.yaml"), []byte(miniSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`version: 1
target: { baseUrl: "%s", spec: ./openapi.yaml }
scope: { allowHosts: ["%s"], acknowledgeAuthorization: true }
safety: { rate: 1000, concurrency: 2 }
profiles:
  alice:
    role: user
    auth: { type: bearer, token: "${env:AD_TEST_ALICE}" }
    owns: { orderId: ["101"] }
    identifiers: ["alice@example.com"]
  bob:
    role: user
    auth: { type: bearer, token: "${env:AD_TEST_BOB}" }
    owns: { orderId: ["201"] }
    identifiers: ["bob@example.com"]
  anonymous:
    role: anonymous
    auth: { type: none }
output: { formats: [json], dir: "%s" }
%s`, api.URL, api.host(), filepath.ToSlash(filepath.Join(dir, "out")), extra)
	p := filepath.Join(dir, "authdiff.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// run executes the CLI with args and returns the exit code and output.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return runCtx(t, context.Background(), args...)
}

func runCtx(t *testing.T, ctx context.Context, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := execute(ctx, args, &out, &errb, "1.2.3", "abc123", "2026-11-20")
	return code, out.String(), errb.String()
}

func outDir(cfgPath string) string { return filepath.Join(filepath.Dir(cfgPath), "out") }
