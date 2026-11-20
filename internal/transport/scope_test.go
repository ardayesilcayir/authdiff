package transport

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeNormalization(t *testing.T) {
	cases := []struct {
		name  string
		allow []string
		url   string
		ok    bool
	}{
		{"case-insensitive host", []string{"localhost:8000"}, "http://LOCALHOST:8000/x", true},
		{"other port denied", []string{"localhost:8000"}, "http://localhost:8001/x", false},
		{"default port 80 not 8000", []string{"localhost:8000"}, "http://localhost/x", false},
		{"https default 443", []string{"example.com"}, "https://example.com", true},
		{"http default 80", []string{"example.com"}, "http://example.com/a", true},
		{"upper-case entry", []string{"EXAMPLE.com"}, "https://example.COM/", true},
		{"suffix attack", []string{"example.com"}, "https://example.com.evil.io", false},
		{"prefix attack", []string{"example.com"}, "https://evilexample.com", false},
		{"subdomain denied", []string{"example.com"}, "https://api.example.com", false},
		{"non-default port denied", []string{"example.com"}, "https://example.com:8443", false},
		{"userinfo trick", []string{"example.com"}, "http://example.com@evil.io/", false},
		{"host in query", []string{"example.com"}, "https://evil.io/?h=example.com", false},
		{"trailing dot", []string{"example.com"}, "https://example.com./", true},
		{"explicit 443 entry https", []string{"example.com:443"}, "https://example.com", true},
		{"explicit 443 entry http", []string{"example.com:443"}, "http://example.com", false},
		{"ipv6 with port", []string{"[::1]:8000"}, "http://[::1]:8000/", true},
		{"ipv6 other port", []string{"[::1]:8000"}, "http://[::1]:8001/", false},
		{"ipv6 default port denied", []string{"[::1]:8000"}, "http://[::1]/", false},
		{"ipv6 bare entry", []string{"::1"}, "https://[::1]/", true},
		{"ipv6 long form", []string{"[0:0:0:0:0:0:0:1]:8000"}, "http://[::1]:8000/", true},
		{"port leading zeros", []string{"localhost:8000"}, "http://localhost:08000/", true},
		{"ftp scheme", []string{"example.com"}, "ftp://example.com/", false},
		{"empty allow list", nil, "http://example.com/", false},
		{"blank entries ignored", []string{"", "  "}, "http://example.com/", false},
		{"entry with scheme ignored", []string{"http://example.com"}, "http://example.com/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, n := countingBase()
			rt := NewScope(tc.allow, base)
			resp, err := rt.RoundTrip(mustReq(t, "GET", tc.url, ""))
			if tc.ok {
				require.NoError(t, err)
				_ = resp.Body.Close()
				assert.EqualValues(t, 1, atomic.LoadInt32(n))
				return
			}
			require.ErrorIs(t, err, ErrOutOfScope)
			assert.EqualValues(t, 0, atomic.LoadInt32(n))
		})
	}
}

func TestScopeErrorMentionsHostNotQuery(t *testing.T) {
	base, _ := countingBase()
	rt := NewScope([]string{"example.com"}, base)
	_, err := rt.RoundTrip(mustReq(t, "GET", "http://evil.io/p?apikey=SUPERSECRETVALUE", ""))
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.Contains(t, err.Error(), "evil.io")
	assert.NotContains(t, err.Error(), "SUPERSECRETVALUE")
}

func TestScopeClosesRequestBodyOnBlock(t *testing.T) {
	base, _ := countingBase()
	rt := NewScope([]string{"example.com"}, base)
	closed := false
	req := mustReq(t, "POST", "http://evil.io/", "x")
	req.Body = closeSpy{closed: &closed}
	_, err := rt.RoundTrip(req)
	require.ErrorIs(t, err, ErrOutOfScope)
	assert.True(t, closed)
}

type closeSpy struct{ closed *bool }

func (closeSpy) Read([]byte) (int, error) { return 0, nil }
func (c closeSpy) Close() error           { *c.closed = true; return nil }
