package compare

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimilarity(t *testing.T) {
	j1 := []byte(`{"a":1,"b":2,"c":3}`)

	assert.Equal(t, 1.0, Similarity(j1, j1, Options{}))

	// requestId differs but is dynamic: masked from both sides.
	a := []byte(`{"id":1,"requestId":"x"}`)
	b := []byte(`{"id":1,"requestId":"y"}`)
	assert.Equal(t, 0.5, Similarity(a, b, Options{}))
	assert.Equal(t, 1.0, Similarity(a, b, Options{Dynamic: map[string]bool{"$.requestId": true}}))
	assert.Equal(t, 1.0, Similarity(a, b, Options{IgnoreFields: []string{"$..requestId"}}))

	// 2 common of 4 union paths.
	assert.Equal(t, 0.5, Similarity(j1, []byte(`{"a":1,"b":2,"d":4}`), Options{}))
	// 1 equal of 4 union paths.
	assert.Equal(t, 0.25, Similarity(j1, []byte(`{"a":1,"b":9,"d":3}`), Options{}))
}

func TestSimilarityEmptyUnion(t *testing.T) {
	assert.Equal(t, 1.0, Similarity([]byte(`{}`), []byte(`{}`), Options{}))
	// everything masked -> empty union
	a := []byte(`{"r":1}`)
	b := []byte(`{"r":2}`)
	assert.Equal(t, 1.0, Similarity(a, b, Options{IgnoreFields: []string{"$.r"}}))
}

func TestSimilarityNonJSON(t *testing.T) {
	assert.Equal(t, 1.0, Similarity(nil, nil, Options{}))
	assert.Equal(t, 1.0, Similarity([]byte{}, []byte(""), Options{}))
	pdf := []byte("%PDF-1.4 \x00\x01\x02 binary")
	assert.Equal(t, 1.0, Similarity(pdf, append([]byte{}, pdf...), Options{}))

	s := Similarity([]byte("short text"), []byte("a considerably longer text body here"), Options{})
	assert.Less(t, s, 0.85)
	assert.Greater(t, s, 0.0)

	// differing but same length never exceeds 0.8
	assert.InDelta(t, 0.8, Similarity([]byte("aaaa"), []byte("bbbb"), Options{}), 1e-9)
	// empty vs non-empty non-JSON
	assert.Equal(t, 0.0, Similarity([]byte(""), []byte("<html>"), Options{}))
}

func TestSimilarityMixed(t *testing.T) {
	assert.Equal(t, 0.0, Similarity([]byte(`{"a":1}`), []byte("<html>oops</html>"), Options{}))
	assert.Equal(t, 0.0, Similarity([]byte("<html>"), []byte(`{"a":1}`), Options{}))
}
