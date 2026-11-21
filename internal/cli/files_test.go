package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// init writes authdiff.yaml owner-only: it is where users may paste tokens.
func TestInitConfigIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	if code, _, errOut := run(t, "init", "--dir", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	fi, err := os.Stat(filepath.Join(dir, "authdiff.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("authdiff.yaml mode %v, want 0600", fi.Mode().Perm())
	}
}

const ctrlSpec = `openapi: 3.0.3
info: { title: ctrl, version: "1" }
paths:
  "/evil\u001b[2J{id}":
    get:
      operationId: "op\u0007x"
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      responses: { "200": { description: ok } }
`

// Control characters from the spec never reach the terminal.
func TestInventoryAndDryRunStripControlChars(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	if err := os.WriteFile(filepath.Join(filepath.Dir(p), "openapi.yaml"), []byte(ctrlSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"inventory", "-c", p}, {"scan", "-c", p, "--dry-run"}} {
		code, out, errOut := run(t, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, errOut)
		}
		if strings.ContainsAny(out, "\x1b\x07") {
			t.Errorf("%v printed control characters: %q", args, out)
		}
		if !strings.Contains(out, "/evil[2J") {
			t.Errorf("%v: path missing: %q", args, out)
		}
	}
}
