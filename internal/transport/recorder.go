package transport

import (
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/ardayesilcayir/authdiff/internal/finding"
)

// maxEvidenceBytes caps each body stored in an Exchange.
const maxEvidenceBytes = 16 * 1024

// truncateEvidence cuts s to maxEvidenceBytes without splitting a UTF-8 rune.
func truncateEvidence(s string) (string, bool) {
	if len(s) <= maxEvidenceBytes {
		return s, false
	}
	cut := maxEvidenceBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// record builds the masked evidence for one request/response pair. Secrets are
// redacted before truncation so a cut can never leave a secret fragment.
func record(d *redactor, req *http.Request, reqBody []byte, status int, respHeader http.Header,
	respBody []byte, dur time.Duration, truncated bool) finding.Exchange {
	reqText, cutReq := truncateEvidence(d.String(string(reqBody)))
	respText, cutResp := truncateEvidence(d.String(string(respBody)))
	return finding.Exchange{
		Method:          req.Method,
		URL:             d.String(req.URL.Redacted()),
		RequestHeaders:  d.Headers(req.Header),
		RequestBody:     reqText,
		Status:          status,
		ResponseHeaders: d.Headers(respHeader),
		ResponseBody:    respText,
		DurationMs:      dur.Milliseconds(),
		Truncated:       truncated || cutReq || cutResp,
	}
}
