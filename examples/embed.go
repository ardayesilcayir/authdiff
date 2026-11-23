// Package examplesfs embeds the example config and the vuln-lab's fake
// tokens so `authdiff ui` can create the demo project without the repository
// on disk.
package examplesfs

import "embed"

// FS holds authdiff.yaml and vuln-lab.env from this directory.
//
//go:embed authdiff.yaml vuln-lab.env
var FS embed.FS
