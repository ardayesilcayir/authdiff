// Package cli implements the authdiff command line (cobra).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// Exit codes (see the global constraints).
const (
	exitOK     = 0
	exitFailOn = 1
	exitError  = 2
)

// codeError carries an exit code. A nil err means the message was already
// printed.
type codeError struct {
	code int
	err  error
}

func (e *codeError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *codeError) Unwrap() error { return e.err }

// app holds what every command shares.
type app struct {
	stdout, stderr        io.Writer
	version, commit, date string

	verbose   bool
	logFormat string
	noColor   bool
	log       *slog.Logger
}

// Execute runs the CLI with args and returns the process exit code. Ctrl-C
// or SIGTERM cancels the running command.
func Execute(args []string, stdout, stderr io.Writer, version, commit, date string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return execute(ctx, args, stdout, stderr, version, commit, date)
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer, version, commit, date string) int {
	a := &app{stdout: stdout, stderr: stderr, version: version, commit: commit, date: date}
	root := a.rootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	var ce *codeError
	if errors.As(err, &ce) {
		if ce.err != nil {
			fmt.Fprintln(stderr, "Error:", ce.err)
		}
		return ce.code
	}
	fmt.Fprintln(stderr, "Error:", err)
	return exitError
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "authdiff",
		Short:         "Find authorization bugs (BOLA, BFLA, missing auth, mass assignment) in REST APIs",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return a.setupLogging()
		},
	}
	pf := root.PersistentFlags()
	pf.BoolVarP(&a.verbose, "verbose", "v", false, "enable debug logging")
	pf.StringVar(&a.logFormat, "log-format", "text", "log format on stderr: text or json")
	pf.BoolVar(&a.noColor, "no-color", false, "disable colored terminal output")
	root.AddCommand(a.initCmd(), a.inventoryCmd(), a.scanCmd(), a.rulesCmd(), a.reportCmd(), a.versionCmd())
	return root
}

func (a *app) setupLogging() error {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if a.verbose {
		opts.Level = slog.LevelDebug
	}
	switch a.logFormat {
	case "text":
		a.log = slog.New(slog.NewTextHandler(a.stderr, opts))
	case "json":
		a.log = slog.New(slog.NewJSONHandler(a.stderr, opts))
	default:
		return fmt.Errorf("--log-format must be text or json, got %q", a.logFormat)
	}
	return nil
}

// color reports whether terminal output may use ANSI colors: not disabled by
// --no-color or NO_COLOR, and stdout is a terminal.
func (a *app) color() bool {
	if a.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := a.stdout.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
