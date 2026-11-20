package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/ardayesilcayir/authdiff/internal/identity"
	"github.com/ardayesilcayir/authdiff/internal/planner"
	"github.com/ardayesilcayir/authdiff/internal/transport"
)

// Sender sends a built request as a profile.
type Sender interface {
	Send(ctx context.Context, p *identity.Profile, step string, r planner.Request) (*transport.Response, error)
}

type clientSender struct{ c *transport.Client }

// NewSender returns a Sender that sends through c.
func NewSender(c *transport.Client) Sender { return &clientSender{c: c} }

// Send builds the http.Request, injects p's credentials, sends it and labels
// the recorded exchange with the step and profile names.
func (s *clientSender) Send(ctx context.Context, p *identity.Profile, step string, r planner.Request) (*transport.Response, error) {
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", r.Method, r.Path, err)
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	name := ""
	if p != nil {
		p.Apply(req)
		name = p.Name
	}
	resp, err := s.c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	resp.Exchange.Step = step
	resp.Exchange.Profile = name
	return resp, nil
}
