// Package compare implements the response comparison primitives used by the
// authdiff engine: JSON flattening, dynamic-field detection, a similarity
// score and ownership evidence. It uses only the standard library.
package compare

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxDepth is the deepest container nesting that Flatten descends into.
// Anything nested deeper is collapsed into a single depthLimitLeaf leaf.
const maxDepth = 64

const depthLimitLeaf = "<depth-limit>"

// maxLeaves caps the leaves Flatten collects; the rest of a larger document
// is dropped and a single leafLimitLeaf marks the cut.
const maxLeaves = 50000

// maxPathBytes caps the total size of all collected paths, so many leaves
// under long or deep keys cannot exhaust memory either.
const maxPathBytes = 32 * 1024 * 1024

// maxKeyLen is the longest object key kept in a path; longer keys are cut.
const maxKeyLen = 256

const leafLimitLeaf = "<leaf-limit>"

// leaf is one scalar (or empty container) found while flattening JSON.
type leaf struct {
	canon string // canonical JSON text, e.g. `"abc"`, `12`, `{}`
	raw   string // unquoted value used for evidence matching
}

// parseJSON decodes body as exactly one JSON value, preserving numbers as
// json.Number. encoding/json itself rejects nesting beyond 10000 levels.
func parseJSON(body []byte) (any, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false // trailing data
	}
	return v, true
}

// flattenLeaves parses body and returns its path -> leaf map.
func flattenLeaves(body []byte) (map[string]leaf, bool) {
	v, ok := parseJSON(body)
	if !ok {
		return nil, false
	}
	w := &walker{out: make(map[string]leaf)}
	w.walk(v, "$", 0)
	return w.out, true
}

// walker collects leaves up to maxLeaves / maxPathBytes; object keys are
// visited in sorted order so a cut keeps the same leaves every time.
type walker struct {
	out   map[string]leaf
	bytes int
	full  bool
}

// add records one leaf, or the leaf-limit marker once a cap is reached.
func (w *walker) add(path string, l leaf) {
	if w.full {
		return
	}
	if len(w.out) >= maxLeaves || w.bytes+len(path) > maxPathBytes {
		w.full = true
		w.out[path] = leaf{canon: leafLimitLeaf, raw: leafLimitLeaf}
		return
	}
	w.bytes += len(path)
	w.out[path] = l
}

// walk recurses at most maxDepth levels, so the stack stays bounded no matter
// how deep the input is.
func (w *walker) walk(v any, path string, depth int) {
	if w.full {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 {
			w.add(path, leaf{canon: "{}", raw: "{}"})
			return
		}
		if depth >= maxDepth {
			w.add(path, leaf{canon: depthLimitLeaf, raw: depthLimitLeaf})
			return
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.walk(t[k], path+"."+truncKey(k), depth+1)
		}
	case []any:
		if len(t) == 0 {
			w.add(path, leaf{canon: "[]", raw: "[]"})
			return
		}
		if depth >= maxDepth {
			w.add(path, leaf{canon: depthLimitLeaf, raw: depthLimitLeaf})
			return
		}
		for i, c := range t {
			w.walk(c, path+"["+strconv.Itoa(i)+"]", depth+1)
		}
	case string:
		w.add(path, leaf{canon: quote(t), raw: t})
	case json.Number:
		w.add(path, leaf{canon: t.String(), raw: t.String()})
	case bool:
		s := strconv.FormatBool(t)
		w.add(path, leaf{canon: s, raw: s})
	default: // nil
		w.add(path, leaf{canon: "null", raw: "null"})
	}
}

// truncKey cuts a key to maxKeyLen bytes without splitting a UTF-8 rune.
func truncKey(k string) string {
	if len(k) <= maxKeyLen {
		return k
	}
	cut := maxKeyLen
	for cut > 0 && !utf8.RuneStart(k[cut]) {
		cut--
	}
	return k[:cut]
}

func quote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // encoding a string cannot fail
	return strings.TrimSuffix(buf.String(), "\n")
}

// Flatten parses body as JSON and returns a map from JSONPath-like path
// (e.g. "$.items[0].price") to the canonical JSON text of each leaf. Empty
// objects and arrays are leaves ("{}" / "[]"); branches nested deeper than 64
// levels collapse into a single "<depth-limit>" leaf. At most 50,000 leaves
// are kept (a "<leaf-limit>" leaf marks the cut) and object keys longer than
// 256 bytes are truncated in paths. It returns (nil, false)
// when body is not a single valid JSON value (including input that
// encoding/json refuses for excessive nesting).
func Flatten(body []byte) (map[string]string, bool) {
	leaves, ok := flattenLeaves(body)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(leaves))
	for p, l := range leaves {
		out[p] = l.canon
	}
	return out, true
}

type segKind int

const (
	segKey segKind = iota
	segIndex
	segDescent
)

type segment struct {
	kind segKind
	val  string
}

// splitPath tokenizes "$.a[0].b" or "$..x" style paths and patterns.
func splitPath(s string) []segment {
	var segs []segment
	i := 0
	if strings.HasPrefix(s, "$") {
		i = 1
	}
	readKey := func() {
		j := i
		for j < len(s) && s[j] != '.' && s[j] != '[' {
			j++
		}
		segs = append(segs, segment{segKey, s[i:j]})
		i = j
	}
	for i < len(s) {
		switch s[i] {
		case '.':
			if i+1 < len(s) && s[i+1] == '.' {
				segs = append(segs, segment{kind: segDescent})
				i += 2
			} else {
				i++
			}
			if i < len(s) && s[i] != '[' {
				readKey()
			}
		case '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				segs = append(segs, segment{segKey, s[i:]})
				i = len(s)
				break
			}
			segs = append(segs, segment{segIndex, s[i+1 : i+end]})
			i += end + 1
		default:
			readKey()
		}
	}
	return segs
}

func segMatches(p, s segment) bool {
	if p.kind != s.kind {
		return false
	}
	return p.val == "*" || p.val == s.val
}

func matchSegs(p, s []segment, prefixOK bool) bool {
	for len(p) > 0 {
		if p[0].kind == segDescent {
			rest := p[1:]
			for k := 0; k <= len(s); k++ {
				if matchSegs(rest, s[k:], true) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 || !segMatches(p[0], s[0]) {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return prefixOK || len(s) == 0
}

// MatchPath reports whether path matches pattern. "$.a.b" matches exactly;
// "$..x" matches key x at any depth (and everything below it); "[*]" matches
// any array index and ".*" any object key.
func MatchPath(pattern, path string) bool {
	return matchSegs(splitPath(pattern), splitPath(path), false)
}

// DynamicPaths returns the leaf paths whose value differs between a and b or
// that exist in only one of them. Non-JSON input yields an empty set.
func DynamicPaths(a, b []byte) map[string]bool {
	out := map[string]bool{}
	fa, okA := Flatten(a)
	fb, okB := Flatten(b)
	if !okA || !okB {
		return out
	}
	for p, va := range fa {
		if vb, ok := fb[p]; !ok || vb != va {
			out[p] = true
		}
	}
	for p := range fb {
		if _, ok := fa[p]; !ok {
			out[p] = true
		}
	}
	return out
}
