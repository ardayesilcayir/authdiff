package report

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Reports contain response data: the directory is private and the files are
// owner-only; a symlink in place of a report file is refused.
func TestWritePermissionsAndSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	var buf bytes.Buffer
	if _, err := Write(dir, []string{"json"}, fixture(), &buf, false); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode %v", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Join(dir, "results.json")); fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode %v", fi.Mode().Perm())
		}
	}
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "results.sarif")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := Write(dir, []string{"sarif"}, fixture(), &buf, false)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink not refused: %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "keep" { //nolint:gosec // G304: test-only path under t.TempDir or operator-supplied input
		t.Error("symlink target overwritten")
	}
}

func TestCleanTerminal(t *testing.T) {
	if got := CleanTerminal("GET /a\x1b[2J\x07b\u009bc\td"); got != "GET /a[2Jbcd" {
		t.Errorf("CleanTerminal = %q", got)
	}
	r := fixture()
	r.Findings[0].Path = "/orders/\x1b]0;pwned\x07{orderId}"
	var buf bytes.Buffer
	if err := WriteTerminal(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b\x07") {
		t.Errorf("control characters printed: %q", buf.String())
	}
}
