package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

var allowedFormats = map[string]bool{"terminal": true, "json": true, "sarif": true, "html": true}

// Validate checks the config and returns all problems joined together.
func Validate(c *Config) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Version != 1 {
		add("version must be 1, got %d", c.Version)
	}
	if strings.TrimSpace(c.Target.BaseURL) == "" {
		add("target.baseUrl is required")
	}
	if strings.TrimSpace(c.Target.Spec) == "" {
		add("target.spec is required")
	}
	if len(c.Scope.AllowHosts) == 0 {
		add("scope.allowHosts must list at least one host")
	}
	if !c.Scope.AcknowledgeAuthorization {
		add("scope.acknowledgeAuthorization must be true (confirm you are authorized to test this system)")
	}
	if c.Target.BaseURL != "" && len(c.Scope.AllowHosts) > 0 {
		u, err := url.Parse(c.Target.BaseURL)
		if err != nil || u.Host == "" {
			add("target.baseUrl %q is not a valid absolute URL", c.Target.BaseURL)
		} else if !hostAllowed(u, c.Scope.AllowHosts) {
			add("scope.allowHosts does not include the target.baseUrl host %q", u.Host)
		}
	}

	if len(c.Profiles) == 0 {
		add("at least one profile is required")
	}
	for _, name := range c.ProfileNames() {
		if err := validateAuth(c.Profiles[name].Auth); err != nil {
			add("profile %q: %v", name, err)
		}
	}

	if c.Safety.Rate <= 0 {
		add("safety.rate must be > 0")
	}
	if c.Safety.Concurrency < 1 {
		add("safety.concurrency must be >= 1")
	}
	if c.Safety.Proxy != "" {
		if err := validateProxy(c.Safety.Proxy); err != nil {
			add("safety.proxy: %v", err)
		}
	}
	if c.Compare.SimilarityThreshold < 0 || c.Compare.SimilarityThreshold > 1 {
		add("compare.similarityThreshold must be within [0,1]")
	}
	if c.Output.FailOn != "" {
		if _, err := finding.ParseSeverity(c.Output.FailOn); err != nil {
			add("output.failOn: %v", err)
		}
	}
	for _, f := range c.Output.Formats {
		if !allowedFormats[f] {
			add("output.formats: unknown format %q (allowed: terminal,json,sarif,html)", f)
		}
	}
	return errors.Join(errs...)
}

func validateAuth(a Auth) error {
	switch a.Type {
	case "bearer":
		if a.Token == "" {
			return errors.New("auth.token is required for bearer")
		}
	case "cookie":
		// An empty Name means Token is the full Cookie header value.
		if a.Token == "" {
			return errors.New("auth.token is required for cookie")
		}
	case "apikey":
		// Name is optional; identity.Apply supplies the default.
		if a.Token == "" {
			return errors.New("auth.token is required for apikey")
		}
		if a.In != "" && a.In != "header" && a.In != "query" {
			return fmt.Errorf("auth.in must be header or query, got %q", a.In)
		}
	case "basic":
		if a.Username == "" {
			return errors.New("auth.username is required for basic")
		}
	case "none":
	default:
		return fmt.Errorf("unknown auth type %q (want bearer, cookie, apikey, basic or none)", a.Type)
	}
	return nil
}

// validateProxy accepts an http, https or socks5 URL with a host. The
// message never quotes the URL, which may carry credentials.
func validateProxy(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return errors.New("not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
	default:
		return errors.New("scheme must be http, https or socks5")
	}
	if u.Host == "" {
		return errors.New("URL has no host")
	}
	return nil
}

func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

// hostAllowed reports whether u's host:port matches an allowHosts entry.
// Comparison is case-insensitive; a missing port means the scheme default.
func hostAllowed(u *url.URL, allow []string) bool {
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	want := strings.ToLower(u.Hostname())
	for _, entry := range allow {
		entry = strings.ToLower(strings.TrimSpace(entry))
		h, p, err := net.SplitHostPort(entry)
		if err != nil {
			h, p = strings.Trim(entry, "[]"), defaultPort(u.Scheme)
		}
		if h == want && p == port {
			return true
		}
	}
	return false
}
