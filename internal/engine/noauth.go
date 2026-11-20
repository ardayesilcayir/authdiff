package engine

import (
	"sort"

	"github.com/ardayesilcayir/authdiff/internal/identity"
)

// RuleNOAUTH is the built-in missing-authentication rule ID.
const RuleNOAUTH = "AD-NOAUTH-001"

// allIdentifiers is the sorted union of every profile's identifiers, exposed
// to rules as "identifiers" so NOAUTH can spot any user's data in an
// anonymous response.
func allIdentifiers(ps []*identity.Profile) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range ps {
		for _, id := range p.Identifiers {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}
