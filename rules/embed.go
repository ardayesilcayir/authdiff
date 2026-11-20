// Package rulesfs embeds the built-in authdiff rule templates.
package rulesfs

import "embed"

// FS holds the built-in rule YAML files.
//
//go:embed *.yaml
var FS embed.FS
