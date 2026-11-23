package ui

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// labTimeout bounds the demo lab check.
const labTimeout = 2 * time.Second

// CheckLab reports whether the demo lab answers GET <labURL>/openapi.json
// with 200 within two seconds. Only loopback hosts are contacted, no proxy
// is used and redirects are not followed.
func CheckLab(ctx context.Context, labURL string) bool {
	u, err := url.Parse(strings.TrimRight(labURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !isLoopbackHost(u.Hostname()) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, labTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String()+"/openapi.json", nil)
	if err != nil {
		return false
	}
	c := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Do(req) //nolint:gosec // G704: host is restricted to loopback above
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
