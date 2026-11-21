package authdiff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://u:p4ss@h/openapi.json?api_key=K&v=1": "https://h/openapi.json?api_key=****&v=****",
		"HTTP://tok@h:8000/x":                         "http://h:8000/x",
		"http://h/api":                                "http://h/api",
		"./openapi.yaml":                              "./openapi.yaml",
		"http://h/%zz":                                "****",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestURLSecrets(t *testing.T) {
	cfg := &config.Config{Target: config.Target{
		BaseURL: "http://scanner:longpassword@h",
		Spec:    "https://tokenonly@h/s.json?api_key=abcdefgh123&v=1",
	}}
	got := strings.Join(urlSecrets(cfg, false), ",")
	if got != "longpassword,tokenonly,abcdefgh123" {
		t.Errorf("urlSecrets(evidence) = %q", got)
	}
	if all := urlSecrets(cfg, true); len(all) != 4 {
		t.Errorf("urlSecrets(all) = %v", all)
	}
}

func TestScrubberErr(t *testing.T) {
	cfg := &config.Config{Target: config.Target{Spec: "http://h/s.json?api_key=abc%2Fdef"}}
	sc := newScrubber(cfg)
	err := sc.Err(fmt.Errorf("fetch http://h/s.json?api_key=abc%%2Fdef: %w", context.Canceled))
	if strings.Contains(err.Error(), "abc") || !errors.Is(err, context.Canceled) {
		t.Errorf("scrubbed = %v (is canceled %v)", err, errors.Is(err, context.Canceled))
	}
	if e := errors.New("clean"); sc.Err(e) != e || sc.Err(nil) != nil {
		t.Error("clean errors must pass through unchanged")
	}
	if (&scrubber{}).String("x") != "x" {
		t.Error("empty scrubber changed text")
	}
}

func TestUATransportKeepsExplicitUA(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	c := &http.Client{Transport: &uaTransport{ua: UserAgent(""), next: http.DefaultTransport}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "custom")
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.HasPrefix(got[0], "authdiff/dev ") || got[1] != "custom" {
		t.Errorf("user agents = %v", got)
	}
}

func TestPlanContextCanceledURLSpec(t *testing.T) {
	api := newMiniAPI(t)
	p := writeProject(t, api, "")
	cfgSpecURL(t, p, api.URL+"/openapi.yaml")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanContext(ctx, ScanOptions{ConfigPath: p}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if api.hits.Load() != 0 {
		t.Errorf("canceled plan sent %d requests", api.hits.Load())
	}
}
