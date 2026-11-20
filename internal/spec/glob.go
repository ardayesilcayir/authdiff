package spec

import (
	"path"
	"strings"
)

// MatchGlob reports whether an endpoint path matches a glob pattern.
// "*" matches exactly one path segment (or part of one, e.g. "pre*"), "**"
// matches zero or more segments. "{param}" segments are matched literally.
// Leading, trailing and duplicate slashes are ignored.
func MatchGlob(pattern, p string) bool {
	return matchSegments(splitSegments(pattern), splitSegments(p))
}

// MatchEndpoint matches a pattern against an endpoint. The pattern may be
// prefixed with an HTTP method ("GET /admin/**"); "*" or no prefix matches any
// method. Method comparison is case-insensitive.
func MatchEndpoint(pattern string, e Endpoint) bool {
	pattern = strings.TrimSpace(pattern)
	if i := strings.IndexAny(pattern, " \t"); i > 0 {
		method := pattern[:i]
		if method != "*" && !strings.EqualFold(method, e.Method) {
			return false
		}
		pattern = strings.TrimSpace(pattern[i+1:])
	}
	return MatchGlob(pattern, e.Path)
}

func splitSegments(s string) []string {
	var out []string
	for _, seg := range strings.Split(s, "/") {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

func matchSegments(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for len(pat) > 0 && pat[0] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegments(pat, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 || !matchSegment(pat[0], segs[0]) {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}

func matchSegment(pattern, seg string) bool {
	if pattern == seg {
		return true
	}
	ok, err := path.Match(pattern, seg)
	return err == nil && ok
}
