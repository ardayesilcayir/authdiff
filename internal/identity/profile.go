// Package identity models the profiles (identities) a scan acts as, injects
// their credentials into requests, and tracks which object IDs each owns.
package identity

import (
	"sort"

	"github.com/ardayesilcayir/authdiff/internal/config"
)

// Profile is one identity used during a scan.
type Profile struct {
	Name        string
	Role        string
	Auth        config.Auth
	Identifiers []string
}

// FromConfig builds profiles sorted by name. Identifiers are the configured
// identifiers plus the profile's owned userId values, unique and sorted.
func FromConfig(c *config.Config) []*Profile {
	out := make([]*Profile, 0, len(c.Profiles))
	for _, name := range c.ProfileNames() {
		cp := c.Profiles[name]
		seen := map[string]bool{}
		var ids []string
		for _, id := range append(append([]string{}, cp.Identifiers...), cp.Owns["userId"]...) {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, &Profile{Name: name, Role: cp.Role, Auth: cp.Auth, Identifiers: ids})
	}
	return out
}

// IsAnonymous reports whether the profile sends no credentials.
func (p *Profile) IsAnonymous() bool { return p.Auth.Type == "none" }

// IsAdmin reports whether the profile has the admin role.
func (p *Profile) IsAdmin() bool { return p.Role == "admin" }
