package identity

import "net/http"

// Apply injects the profile's credentials into req. Defaults for the cookie
// and apikey names live here, not in config validation.
func (p *Profile) Apply(req *http.Request) {
	a := p.Auth
	switch a.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+a.Token)
	case "cookie":
		if a.Name == "" {
			req.Header.Set("Cookie", a.Token)
		} else {
			req.Header.Set("Cookie", a.Name+"="+a.Token)
		}
	case "apikey":
		name := a.Name
		if a.In == "query" {
			if name == "" {
				name = "api_key"
			}
			q := req.URL.Query()
			q.Set(name, a.Token)
			req.URL.RawQuery = q.Encode()
			return
		}
		if name == "" {
			name = "X-API-Key"
		}
		req.Header.Set(name, a.Token)
	case "basic":
		req.SetBasicAuth(a.Username, a.Password)
	}
}
