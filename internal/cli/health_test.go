package cli

import (
	"strings"
	"testing"
)

// A scan in which no request got an HTTP response tested nothing: exit 2
// with a clear error instead of a green "No findings.".
func TestScanNoResponsesExits2(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	api.Close() // every request now fails with a network error
	code, out, errOut := run(t, "scan", "-c", p, "--format", "terminal")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr %s", code, errOut)
	}
	if !strings.Contains(errOut, "no request received an HTTP response") {
		t.Errorf("stderr lacks the reason: %q", errOut)
	}
	if !strings.Contains(out, "errors") || !strings.Contains(out, "blocked") {
		t.Errorf("terminal summary lacks blocked/errors: %q", out)
	}
}

// An authenticated profile that never got a 2xx is warned about (its
// credentials are probably wrong).
func TestScanWarnsProfileWithout2xx(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	editConfig(t, p, `token: "${env:AD_TEST_BOB}"`, `token: "wrong-token-xyz-0000"`)
	code, _, errOut := run(t, "scan", "-c", p, "--format", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(errOut, "never received a 2xx") || !strings.Contains(errOut, "profile=bob") {
		t.Errorf("no warning for bob: %q", errOut)
	}
	if strings.Contains(errOut, "profile=alice") {
		t.Errorf("alice wrongly warned: %q", errOut)
	}
}
