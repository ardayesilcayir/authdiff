//go:build tools

// Package tools pins dependencies that later tasks import.
package tools

import (
	_ "github.com/charmbracelet/lipgloss"
	_ "github.com/expr-lang/expr"
	_ "github.com/getkin/kin-openapi/openapi3"
	_ "github.com/spf13/cobra"
	_ "github.com/stretchr/testify/assert"
	_ "github.com/stretchr/testify/require"
	_ "github.com/tidwall/gjson"
	_ "golang.org/x/sync/errgroup"
	_ "golang.org/x/time/rate"
	_ "gopkg.in/yaml.v3"
)
