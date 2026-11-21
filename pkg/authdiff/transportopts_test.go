package authdiff

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// --insecure is never silent: a warning is logged and the result carries a
// note that every report shows.
func TestScanInsecureWarnsAndNotes(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	var logs bytes.Buffer
	res, err := Scan(context.Background(), ScanOptions{
		ConfigPath: p, Overrides: Overrides{Insecure: ptr(true)},
		Log: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "TLS verification disabled") {
		t.Errorf("no insecure warning: %s", logs.String())
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "TLS verification disabled") {
		t.Errorf("notes = %v", res.Notes)
	}
}

// A proxy is used only when configured, and that is logged (credentials in
// the proxy URL are not).
func TestProxyConfigAndOverride(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	cfg, err := LoadConfig(p, Overrides{Proxy: ptr("http://user:pw-secret@proxy.example:3128")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Safety.Proxy != "http://user:pw-secret@proxy.example:3128" {
		t.Errorf("proxy = %q", cfg.Safety.Proxy)
	}
	var logs bytes.Buffer
	if _, err := newClient(cfg, "t", slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "proxy.example:3128") || strings.Contains(logs.String(), "pw-secret") {
		t.Errorf("proxy log = %s", logs.String())
	}
	if _, err := LoadConfig(p, Overrides{Proxy: ptr("ftp://proxy.example")}); err == nil {
		t.Error("ftp proxy accepted")
	}
}
