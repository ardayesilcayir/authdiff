package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

func TestHeatmapMatchesReport(t *testing.T) {
	r := fixture()
	hm, err := Heatmap(r)
	require.NoError(t, err)
	require.NotEmpty(t, hm)
	assert.True(t, strings.HasPrefix(string(hm), `<ul class="legend"`), "got %.60s", hm)
	assert.Contains(t, string(hm), `<div class="cell unexpected">`)

	var buf bytes.Buffer
	require.NoError(t, WriteHTML(&buf, r))
	assert.Contains(t, buf.String(), string(hm), "the report must contain the shared heatmap markup")
}

func TestHeatmapEscapesAndEmpty(t *testing.T) {
	r := &finding.Result{Profiles: []string{"<b>x</b>"}, Matrix: []finding.MatrixCell{{Endpoint: "GET /<script>", Profile: "<b>x</b>", Status: 200, Outcome: finding.Allowed}}}
	hm, err := Heatmap(r)
	require.NoError(t, err)
	assert.NotContains(t, string(hm), "<script>")
	assert.Contains(t, string(hm), "&lt;script&gt;")

	hm, err = Heatmap(&finding.Result{})
	require.NoError(t, err)
	assert.Empty(t, hm)
}
