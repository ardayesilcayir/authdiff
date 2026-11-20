package compare

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlatten(t *testing.T) {
	got, ok := Flatten([]byte(`{"items":[{"price":5}],"a":{}}`))
	require.True(t, ok)
	assert.Equal(t, map[string]string{"$.items[0].price": "5", "$.a": "{}"}, got)
}

func TestFlattenLeafKinds(t *testing.T) {
	got, ok := Flatten([]byte(`{"s":"abc","n":12.50,"big":12345678901234567890,"t":true,"z":null,"e":[],"h":"<a&b>"}`))
	require.True(t, ok)
	assert.Equal(t, map[string]string{
		"$.s": `"abc"`, "$.n": "12.50", "$.big": "12345678901234567890",
		"$.t": "true", "$.z": "null", "$.e": "[]", "$.h": `"<a&b>"`,
	}, got)
}

func TestFlattenTopLevelScalarAndArray(t *testing.T) {
	got, ok := Flatten([]byte(` 7 `))
	require.True(t, ok)
	assert.Equal(t, map[string]string{"$": "7"}, got)

	got, ok = Flatten([]byte(`[1,[2]]`))
	require.True(t, ok)
	assert.Equal(t, map[string]string{"$[0]": "1", "$[1][0]": "2"}, got)
}

func TestFlattenNotJSON(t *testing.T) {
	for _, in := range []string{"", "   ", "<html>", `{"a":`, `{"a":1} trailing`, `{"a":1}{"b":2}`} {
		got, ok := Flatten([]byte(in))
		assert.False(t, ok, in)
		assert.Nil(t, got, in)
	}
}

func TestFlattenDepthLimit(t *testing.T) {
	// 70 nested arrays around a scalar: the branch below depth 64 collapses.
	in := strings.Repeat("[", 70) + "1" + strings.Repeat("]", 70)
	got, ok := Flatten([]byte(in))
	require.True(t, ok)
	require.Len(t, got, 1)
	for k, v := range got {
		assert.Equal(t, "<depth-limit>", v)
		assert.Equal(t, 64, strings.Count(k, "[0]"))
	}

	// Exactly at the limit is kept as a normal leaf.
	in = strings.Repeat("[", 64) + "1" + strings.Repeat("]", 64)
	got, ok = Flatten([]byte(in))
	require.True(t, ok)
	for _, v := range got {
		assert.Equal(t, "1", v)
	}
}

func TestFlattenHugeNestingDoesNotCrash(t *testing.T) {
	for _, n := range []int{10000, 100000} {
		in := strings.Repeat("[", n) + strings.Repeat("]", n)
		assert.NotPanics(t, func() {
			got, ok := Flatten([]byte(in))
			if ok {
				assert.Len(t, got, 1)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"$.a.b", "$.a.b", true},
		{"$.a.b", "$.a.c", false},
		{"$.a.b", "$.a.b.c", false},
		{"$..updatedAt", "$.items[3].updatedAt", true},
		{"$..updatedAt", "$.updatedAt", true},
		{"$..updatedAt", "$.updatedAt.x", true},
		{"$..updatedAt", "$.items[3].created", false},
		{"$.requestId", "$.x.requestId", false},
		{"$.items[*].id", "$.items[7].id", true},
		{"$.items[*].id", "$.items[7].name", false},
		{"$.items[*].id", "$.items.id", false},
		{"$.a.*", "$.a.zzz", true},
		{"$.a.*", "$.a[0]", false},
		{"$.a.*.c", "$.a.b.c", true},
		{"$.a.*.c", "$.a.b.d", false},
		{"$..items[*].id", "$.x.items[2].id", true},
		{"$", "$", true},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, MatchPath(c.pattern, c.path), "%s vs %s", c.pattern, c.path)
	}
}

func TestDynamicPaths(t *testing.T) {
	a := []byte(`{"id":1,"requestId":"r1","ts":100,"items":[{"p":1}]}`)
	b := []byte(`{"id":1,"requestId":"r2","ts":200,"items":[{"p":1}]}`)
	assert.Equal(t, map[string]bool{"$.requestId": true, "$.ts": true}, DynamicPaths(a, b))
}

func TestDynamicPathsOneSidedAndNonJSON(t *testing.T) {
	got := DynamicPaths([]byte(`{"a":1,"x":2}`), []byte(`{"a":1,"y":3}`))
	assert.Equal(t, map[string]bool{"$.x": true, "$.y": true}, got)
	assert.Empty(t, DynamicPaths([]byte("<html>"), []byte(`{"a":1}`)))
}
