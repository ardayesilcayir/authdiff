package engine

import "github.com/ardayesilcayir/authdiff/internal/rules"

// RuleBFLA is the built-in BFLA rule ID.
const RuleBFLA = "AD-BFLA-001"

// idSource is the profile whose object IDs fill a step's path parameters: the
// profile bound to the step's "use" role. For BFLA the admin step uses
// low_priv, so both the admin baseline and the attacker address the
// low-privileged user's own objects (e.g. alice deletes /admin/users/<her id>)
// instead of somebody else's; the planner falls back to other owners when the
// profile owns none. An unbound role yields "" (planner fallback only).
func idSource(s rules.Step, b binding) string {
	if p := b[s.Use]; p != nil {
		return p.Name
	}
	return ""
}
