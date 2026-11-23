package cli

import (
	"os/exec"
	"runtime"
)

// openBrowser opens url in the default browser. Tests replace it.
var openBrowser = func(url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	cmd := exec.Command(name, args...) //nolint:gosec // G204: fixed opener; the URL is our own loopback session URL
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// browserCommand is the platform's "open this URL" command.
func browserCommand(goos, url string) (string, []string) {
	switch goos {
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		return "open", []string{url}
	default:
		return "xdg-open", []string{url}
	}
}
