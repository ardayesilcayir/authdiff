package engine

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// Sensitive keys are matched on word segments, not substrings.
func TestLeakKeySegments(t *testing.T) {
	sensitive := []string{"passwordHash", "password_hash", "api_key", "apiKey", "APIKey", "x-api-key", "ssn",
		"accessToken", "refresh_token", "clientSecret", "passwd", "Token", "secret_hash", "userSSN"}
	benign := []string{"businessName", "hashtag", "tokenType", "token_type", "nextPageToken", "tokenCount",
		"tokenExpiresAt", "token_expiry", "pageToken", "classname", "assessment", "passport", "apiVersion", "keyId"}
	var b strings.Builder
	b.WriteString("{")
	all := append(append([]string{}, sensitive...), benign...)
	for i, k := range all {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + k + `":"v"`)
	}
	b.WriteString("}")
	got := sensitiveKeys([]byte(b.String()), nil)
	want := append([]string{}, sensitive...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys =\n %v\nwant\n %v", got, want)
	}
}

// Harvest rules for endpoints outside the filtered inventory are not sent.
func TestHarvestHonoursFilter(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
	})
	cfg := testConfig(api.URL)
	cfg.Harvest = []config.HarvestRule{{Endpoint: "GET /me/orders", Extract: map[string]string{"id": "$.items[*].id"}}}
	runScan(t, api, cfg, []spec.Endpoint{epGetOrder}, templateRules(t, RuleBOLARead))
	for _, h := range api.Hits() {
		if h.Path == "/me/orders" {
			t.Fatalf("harvest sent for an endpoint outside the inventory: %+v", h)
		}
	}
}
