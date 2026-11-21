package engine

import (
	"context"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ardayesilcayir/authdiff/internal/compare"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/rules"
	"github.com/ardayesilcayir/authdiff/internal/spec"
)

// RuleLeak is the built-in sensitive data exposure rule ID.
const RuleLeak = "AD-LEAK-001"

func init() {
	registry[rules.KindLeak] = func(r *rules.Rule) Check { return &leakCheck{rule: r} }
}

// sensitiveSegments are the word segments of a JSON key that name secrets.
var sensitiveSegments = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true, "apikey": true, "ssn": true, "hash": true,
}

// tokenMetaSegments mark a "token" key as metadata about a token (its type,
// count, expiry or a pagination cursor) rather than the token itself.
var tokenMetaSegments = map[string]bool{
	"type": true, "count": true, "page": true, "next": true, "expires": true, "expiry": true,
}

// indexSuffixRe matches trailing array indices of a flattened path.
var indexSuffixRe = regexp.MustCompile(`(\[\d+\])+$`)

// leakCheck reads each GET endpoint as any_user and reports response keys
// that look sensitive and are not declared in the response schema.
type leakCheck struct{ rule *rules.Rule }

func (c *leakCheck) Rule() *rules.Rule { return c.rule }

func (c *leakCheck) Phase(spec.Endpoint) int { return 1 }

func (c *leakCheck) Applies(ep spec.Endpoint, env *Env) bool {
	return ep.Method == http.MethodGet && ruleApplies(c.rule.Applies, ep, env)
}

func (c *leakCheck) Plan(ep spec.Endpoint, env *Env) []PlannedRequest {
	p := anyUser(ep, env)
	if p == nil {
		return nil
	}
	req, err := env.Builder.Build(ep, http.MethodGet, p.Name, nil)
	if err != nil {
		env.logger().Warn("plan: build request", "rule", c.rule.ID, "endpoint", ep.Key(), "err", err)
		return nil
	}
	return []PlannedRequest{{RuleID: c.rule.ID, Endpoint: ep.Key(), Step: "leak", Profile: p.Name,
		Method: http.MethodGet, Path: req.Path}}
}

func (c *leakCheck) Run(ctx context.Context, ep spec.Endpoint, env *Env) (Outcome, error) {
	var out Outcome
	p := anyUser(ep, env)
	if p == nil {
		return out, nil
	}
	req, err := env.Builder.Build(ep, http.MethodGet, p.Name, nil)
	if err != nil {
		out.Observations = append(out.Observations, buildFailed(env, c.rule.ID, ep, http.MethodGet, p.Name, "leak", err))
		return out, nil
	}
	resp, o, err := probe(ctx, env, c.rule.ID, p, "leak", req)
	out.Observations = append(out.Observations, o)
	if err != nil || resp == nil || !isOK(resp.Status) {
		return out, err
	}
	keys := sensitiveKeys(resp.Body, ep.ResponseFields)
	if len(keys) == 0 {
		return out, nil
	}
	f := newFinding(c.rule, ep, ep.Method, p.Name, p.Name, finding.ConfMedium)
	f.Description += "\n\nSensitive fields: " + strings.Join(keys, ", ") + "."
	f.Evidence = []finding.Exchange{resp.Exchange}
	out.Findings = append(out.Findings, f)
	return out, nil
}

// isSensitiveKey reports whether a JSON key names a secret. The key is split
// into lower-case word segments (camelCase, snake_case, kebab-case) and a
// segment must equal a sensitive word, or two adjacent segments must form
// "api"+"key"; substrings never match (businessName, hashtag). A key whose
// only sensitive segment is "token" is ignored when it also has a
// type/count/page/next/expires/expiry segment (tokenType, nextPageToken).
func isSensitiveKey(key string) bool {
	segs := keySegments(key)
	token := false
	for i, s := range segs {
		switch {
		case s == "token":
			token = true
		case sensitiveSegments[s], s == "api" && i+1 < len(segs) && segs[i+1] == "key":
			return true
		}
	}
	if !token {
		return false
	}
	for _, s := range segs {
		if tokenMetaSegments[s] {
			return false
		}
	}
	return true
}

// keySegments splits key into lower-case words at non-alphanumeric
// characters and camelCase boundaries ("userSSN" -> user, ssn; "APIKey" ->
// api, key).
func keySegments(key string) []string {
	var out []string
	rs := []rune(key)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			out = append(out, strings.ToLower(string(rs[start:end])))
		}
		start = -1
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := rs[i-1]
		lowerToUpper := unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev))
		acronymEnd := unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(rs) && unicode.IsLower(rs[i+1])
		if lowerToUpper || acronymEnd {
			flush(i)
			start = i
		}
	}
	flush(len(rs))
	return out
}

// sensitiveKeys returns, sorted and unique, the keys of body's JSON leaves
// (last path segment, array indices stripped) that isSensitiveKey accepts
// and that are not in declared. Non-JSON bodies yield nil.
func sensitiveKeys(body []byte, declared []string) []string {
	flat, ok := compare.Flatten(body)
	if !ok {
		return nil
	}
	skip := map[string]bool{}
	for _, d := range declared {
		skip[d] = true
	}
	seen := map[string]bool{}
	var out []string
	for path := range flat {
		p := indexSuffixRe.ReplaceAllString(path, "")
		i := strings.LastIndex(p, ".")
		if i < 0 {
			continue // the root itself, not a key
		}
		key := p[i+1:]
		if seen[key] || skip[key] || !isSensitiveKey(key) {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
