// Package report renders a finding.Result as JSON, SARIF 2.1.0, a single-file
// HTML report or terminal output.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

// WriteJSON writes r as indented (2 spaces) JSON.
func WriteJSON(w io.Writer, r *finding.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// ReadJSON decodes a Result previously written by WriteJSON.
func ReadJSON(rd io.Reader) (*finding.Result, error) {
	var r finding.Result
	if err := json.NewDecoder(rd).Decode(&r); err != nil {
		return nil, fmt.Errorf("decode result json: %w", err)
	}
	return &r, nil
}
