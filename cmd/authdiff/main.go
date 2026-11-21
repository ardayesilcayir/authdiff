// Command authdiff finds authorization bugs in REST APIs.
package main

import (
	"os"

	"github.com/ardayesilcayir/authdiff/internal/cli"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var version, commit, date = "dev", "none", "unknown"

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr, version, commit, date))
}
