package spec

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A spec whose $refs fan out (every schema refers to the next one many times)
// must load quickly: example generation is memoised and budgeted.
func TestLoadRefFanOutIsFast(t *testing.T) {
	var b strings.Builder
	b.WriteString("openapi: 3.0.3\ninfo: {title: fan, version: '1'}\npaths:\n  /x:\n    post:\n")
	b.WriteString("      requestBody:\n        content:\n          application/json:\n            schema: {$ref: '#/components/schemas/S0'}\n")
	b.WriteString("      responses: {'200': {description: ok}}\ncomponents:\n  schemas:\n")
	const levels, fan = 12, 12
	for l := 0; l < levels; l++ {
		fmt.Fprintf(&b, "    S%d:\n      type: object\n      properties:\n", l)
		for f := 0; f < fan; f++ {
			if l == levels-1 {
				fmt.Fprintf(&b, "        p%d: {type: string}\n", f)
			} else {
				fmt.Fprintf(&b, "        p%d: {$ref: '#/components/schemas/S%d'}\n", f, l+1)
			}
		}
	}
	p := filepath.Join(t.TempDir(), "fan.yaml")
	require.NoError(t, os.WriteFile(p, []byte(b.String()), 0o600))
	start := time.Now()
	inv, err := Load(context.Background(), p, nil)
	require.NoError(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
	require.Len(t, inv.Endpoints, 1)
	assert.NotNil(t, inv.Endpoints[0].Body)
}

// A spec larger than maxSpecBytes is an error, never silently truncated.
func TestLoadOversizeSpecErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.yaml")
	data := "openapi: 3.0.3\ninfo: {title: big, version: '1'}\npaths: {}\n# " + strings.Repeat("x", maxSpecBytes) + "\n"
	require.NoError(t, os.WriteFile(p, []byte(data), 0o600))
	_, err := Load(context.Background(), p, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "larger than")
}

func TestFindLineIndex(t *testing.T) {
	src := "paths:\n  /a:\n    get: {}\n  '/b/{id}':\n    get: {}\n  /v1/{name}:cancel:\n    post: {}\n"
	idx := lineIndex([]byte(src))
	assert.Equal(t, 2, idx["/a"])
	assert.Equal(t, 4, idx["/b/{id}"])
	assert.Equal(t, 6, idx["/v1/{name}:cancel"])
	jsonSrc := "{\n  \"paths\": {\n    \"/a\": {\n"
	assert.Equal(t, 3, lineIndex([]byte(jsonSrc))["/a"])
	assert.Equal(t, 1, lineIndex([]byte(`{"/z": {}}`))["/z"])
}
