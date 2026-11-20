package compare

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvidence(t *testing.T) {
	ok, m := Evidence([]byte(`{"id":2,"ownerId":2}`), []string{"2"})
	assert.True(t, ok)
	assert.Equal(t, []string{"2"}, m)

	ok, m = Evidence([]byte(`{"id":2,"qty":2}`), []string{"2"})
	assert.False(t, ok)
	assert.Empty(t, m)

	ok, m = Evidence([]byte("hello alice@vuln.lab bye"), []string{"alice@vuln.lab"})
	assert.True(t, ok)
	assert.Equal(t, []string{"alice@vuln.lab"}, m)
}

func TestEvidenceJSONRules(t *testing.T) {
	// long id matches any key; string leaves are compared unquoted
	ok, m := Evidence([]byte(`{"note":"alice@vuln.lab"}`), []string{"alice@vuln.lab"})
	assert.True(t, ok)
	assert.Equal(t, []string{"alice@vuln.lab"}, m)

	// short id in a string leaf under a keyed owner field, nested in arrays
	ok, _ = Evidence([]byte(`{"items":[{"Customer_ID":"42"}]}`), []string{"42"})
	assert.True(t, ok)

	// short id not equal as whole leaf: no match
	ok, _ = Evidence([]byte(`{"ownerId":"142"}`), []string{"42"})
	assert.False(t, ok)

	// last key through trailing index
	ok, _ = Evidence([]byte(`{"emails":["7"]}`), []string{"7"})
	assert.True(t, ok)

	// dedupe + sort, ignore empty ids
	ok, m = Evidence([]byte(`{"a":"zzzzzz","b":"aaaaaa","c":"zzzzzz"}`), []string{"zzzzzz", "aaaaaa", "zzzzzz", ""})
	assert.True(t, ok)
	assert.Equal(t, []string{"aaaaaa", "zzzzzz"}, m)

	// bool leaves
	ok, _ = Evidence([]byte(`{"owner":true}`), []string{"true"})
	assert.True(t, ok)
}

func TestEvidenceNonJSON(t *testing.T) {
	// short ids never match in plain text
	ok, m := Evidence([]byte("user 2 owns 2"), []string{"2"})
	assert.False(t, ok)
	assert.Empty(t, m)

	ok, m = Evidence([]byte("<html>bob-12345</html>"), []string{"bob-12345", "x"})
	assert.True(t, ok)
	assert.Equal(t, []string{"bob-12345"}, m)

	ok, _ = Evidence(nil, []string{"abcdef"})
	assert.False(t, ok)
	ok, _ = Evidence([]byte(`{"a":1}`), nil)
	assert.False(t, ok)
}
