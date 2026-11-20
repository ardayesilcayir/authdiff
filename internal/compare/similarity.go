package compare

import "bytes"

// Options controls which paths are excluded from a similarity comparison.
type Options struct {
	// IgnoreFields are path patterns (see MatchPath) removed from both sides.
	IgnoreFields []string
	// Dynamic is a set of exact paths removed from both sides.
	Dynamic map[string]bool
}

func (o Options) masked(path string) bool {
	if o.Dynamic[path] {
		return true
	}
	for _, p := range o.IgnoreFields {
		if MatchPath(p, path) {
			return true
		}
	}
	return false
}

// Similarity scores how alike two response bodies are, in [0, 1].
//
// When both are JSON, masked paths are dropped from both sides and the score
// is |paths with equal values| / |union of paths| (1.0 for an empty union).
// When neither is JSON, identical bytes score 1.0 and anything else scores
// 0.8 * min(len)/max(len), so it can never reach the 0.85 default threshold.
// A JSON body against a non-JSON body scores 0.
func Similarity(a, b []byte, o Options) float64 {
	fa, okA := Flatten(a)
	fb, okB := Flatten(b)
	switch {
	case okA && okB:
		return jsonSimilarity(fa, fb, o)
	case okA != okB:
		return 0
	}
	if bytes.Equal(a, b) {
		return 1
	}
	lo, hi := len(a), len(b)
	if lo > hi {
		lo, hi = hi, lo
	}
	return 0.8 * float64(lo) / float64(hi)
}

func jsonSimilarity(fa, fb map[string]string, o Options) float64 {
	union := 0
	equal := 0
	for p, va := range fa {
		if o.masked(p) {
			continue
		}
		union++
		if vb, ok := fb[p]; ok && vb == va {
			equal++
		}
	}
	for p := range fb {
		if o.masked(p) {
			continue
		}
		if _, ok := fa[p]; !ok {
			union++
		}
	}
	if union == 0 {
		return 1
	}
	return float64(equal) / float64(union)
}
