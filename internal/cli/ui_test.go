package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// signalWriter records output and closes ready once a line with the session
// URL appears.
type signalWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if strings.Contains(w.buf.String(), "?key=") {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func (w *signalWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// runUI starts `authdiff ui` with args, waits for the URL, cancels and
// returns the exit code, stdout and the URLs the browser was asked to open.
func runUI(t *testing.T, args ...string) (int, string, []string) {
	t.Helper()
	var opened []string
	var mu sync.Mutex
	orig := openBrowser
	openBrowser = func(u string) error {
		mu.Lock()
		defer mu.Unlock()
		opened = append(opened, u)
		return fmt.Errorf("no browser in tests")
	}
	defer func() { openBrowser = orig }()

	out := &signalWriter{ready: make(chan struct{})}
	var errb bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	code := make(chan int, 1)
	go func() {
		code <- execute(ctx, append([]string{"ui"}, args...), out, &errb, "1.2.3", "abc", "today")
	}()
	select {
	case <-out.ready:
	case c := <-code:
		t.Fatalf("ui exited early with %d: %s", c, errb.String())
	case <-time.After(10 * time.Second):
		t.Fatal("no URL printed")
	}
	cancel()
	select {
	case c := <-code:
		mu.Lock()
		defer mu.Unlock()
		return c, out.String(), opened
	case <-time.After(10 * time.Second):
		t.Fatal("ui did not stop after cancel")
	}
	return 0, "", nil
}

func TestUICommandFlags(t *testing.T) {
	port := freeTCPPort(t)
	code, out, opened := runUI(t, "--no-open", "--port", fmt.Sprint(port), "--projects-dir", t.TempDir())
	if code != 0 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out, fmt.Sprintf("http://127.0.0.1:%d/?key=", port)) {
		t.Errorf("stdout lacks the session URL: %q", out)
	}
	if len(opened) != 0 {
		t.Errorf("--no-open still opened %v", opened)
	}
}

func TestUICommandOpensBrowser(t *testing.T) {
	code, out, opened := runUI(t, "--port", fmt.Sprint(freeTCPPort(t)), "--projects-dir", t.TempDir())
	if code != 0 {
		t.Errorf("exit %d (a browser failure must only warn)", code)
	}
	if len(opened) != 1 || !strings.Contains(out, opened[0]) {
		t.Errorf("opened %v, stdout %q", opened, out)
	}
}

func TestUICommandRejectsBadPort(t *testing.T) {
	if code, _, errOut := run(t, "ui", "--no-open", "--port", "70000"); code != exitError || !strings.Contains(errOut, "port") {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
}

func TestBrowserCommand(t *testing.T) {
	for goos, want := range map[string]string{
		"windows": "rundll32 url.dll,FileProtocolHandler http://x/",
		"darwin":  "open http://x/",
		"linux":   "xdg-open http://x/",
		"freebsd": "xdg-open http://x/",
	} {
		name, args := browserCommand(goos, "http://x/")
		if got := strings.Join(append([]string{name}, args...), " "); got != want {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
	}
}
