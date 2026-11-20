package compare

import (
	"bytes"
	"sort"
	"strings"
)

// minPlainIDLen is the shortest id trusted without a key hint.
const minPlainIDLen = 6

var ownerKeyHints = []string{"owner", "user", "email", "account", "customer"}

// Evidence reports which of ids appear in body as ownership evidence.
//
// In JSON, a leaf matches when its unquoted value equals an id and either the
// id has at least 6 characters or the leaf's last key (lower-cased) contains
// owner, user, email, account or customer. In non-JSON bodies, only ids with
// at least 6 characters are searched as substrings. Matches are unique and
// sorted.
func Evidence(body []byte, ids []string) (bool, []string) {
	found := map[string]bool{}
	if leaves, ok := flattenLeaves(body); ok {
		want := map[string]bool{}
		for _, id := range ids {
			if id != "" {
				want[id] = true
			}
		}
		for p, l := range leaves {
			if !want[l.raw] {
				continue
			}
			if len(l.raw) >= minPlainIDLen || hasOwnerHint(lastKey(p)) {
				found[l.raw] = true
			}
		}
	} else {
		for _, id := range ids {
			if len(id) >= minPlainIDLen && bytes.Contains(body, []byte(id)) {
				found[id] = true
			}
		}
	}
	if len(found) == 0 {
		return false, nil
	}
	out := make([]string, 0, len(found))
	for id := range found {
		out = append(out, id)
	}
	sort.Strings(out)
	return true, out
}

// lastKey returns the last object key of path, ignoring trailing indices.
func lastKey(path string) string {
	segs := splitPath(path)
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i].kind == segKey {
			return segs[i].val
		}
	}
	return ""
}

func hasOwnerHint(key string) bool {
	key = strings.ToLower(key)
	for _, h := range ownerKeyHints {
		if strings.Contains(key, h) {
			return true
		}
	}
	return false
}
