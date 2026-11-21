package cli

import (
	"context"
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ardayesilcayir/authdiff/internal/engine"
	"github.com/ardayesilcayir/authdiff/internal/finding"
	"github.com/ardayesilcayir/authdiff/internal/report"
	"github.com/ardayesilcayir/authdiff/pkg/authdiff"
)

func (a *app) scanCmd() *cobra.Command {
	var (
		cfgPath, ignoreFile, failOn, output string
		proxy                               string
		rate                                float64
		concurrency                         int
		allowDestructive, insecure, dryRun  bool
		formats, include, exclude, tags     []string
		ruleDirs                            []string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run the authorization scan",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			ov := authdiff.Overrides{Formats: formats, Include: include, Exclude: exclude, Tags: tags, RuleDirs: ruleDirs}
			if f.Changed("rate") {
				ov.Rate = &rate
			}
			if f.Changed("concurrency") {
				ov.Concurrency = &concurrency
			}
			if f.Changed("allow-destructive") {
				ov.AllowDestructive = &allowDestructive
			}
			if f.Changed("insecure") {
				ov.Insecure = &insecure
			}
			if f.Changed("proxy") {
				ov.Proxy = &proxy
			}
			if f.Changed("fail-on") {
				ov.FailOn = &failOn
			}
			if f.Changed("output") {
				ov.OutputDir = &output
			}
			opts := authdiff.ScanOptions{
				ConfigPath: cfgPath, IgnoreFile: ignoreFile, Version: a.version, Overrides: ov, Log: a.log,
			}
			if dryRun {
				return a.dryRun(cmd.Context(), opts)
			}
			return a.scan(cmd.Context(), opts)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&cfgPath, "config", "c", "authdiff.yaml", "config file")
	fl.Float64Var(&rate, "rate", 5, "requests per second")
	fl.IntVar(&concurrency, "concurrency", 4, "endpoints tested in parallel")
	fl.BoolVar(&allowDestructive, "allow-destructive", false, "allow DELETE, PUT and PATCH requests")
	fl.BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	fl.StringVar(&proxy, "proxy", "", "send all requests through this proxy URL (HTTP(S)_PROXY are ignored)")
	fl.StringVar(&failOn, "fail-on", "", "exit 1 if an active finding has at least this severity (info|low|medium|high|critical)")
	fl.StringSliceVar(&formats, "format", nil, "report formats, comma separated: terminal,json,sarif,html")
	fl.StringVarP(&output, "output", "o", "", "report output directory")
	fl.StringArrayVar(&include, "include", nil, "only test endpoints matching this glob (repeatable)")
	fl.StringArrayVar(&exclude, "exclude", nil, "skip endpoints matching this glob (repeatable)")
	fl.StringArrayVar(&tags, "tag", nil, "only test operations with this tag (repeatable)")
	fl.StringArrayVar(&ruleDirs, "rules", nil, "directory of custom rule templates (repeatable)")
	fl.StringVar(&ignoreFile, "ignore-file", ".authdiff-ignore", "baseline of suppressed finding IDs")
	fl.BoolVar(&dryRun, "dry-run", false, "print the request plan; sends no requests to the target except downloading the spec when target.spec is a URL")
	return cmd
}

func (a *app) dryRun(ctx context.Context, opts authdiff.ScanOptions) error {
	plan, err := authdiff.PlanContext(ctx, opts)
	if err != nil {
		return err
	}
	return writePlan(a, plan)
}

func writePlan(a *app, plan []engine.PlannedRequest) error {
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSTEP\tPROFILE\tMETHOD\tPATH\tDESTRUCTIVE")
	for _, p := range plan {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.RuleID, p.Step, p.Profile, p.Method, p.Path, yesNo(p.Destructive))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	a.log.Info("dry run: no requests sent to the target", "planned", len(plan))
	return nil
}

func (a *app) scan(ctx context.Context, opts authdiff.ScanOptions) error {
	// Load once up front: it fails fast on config errors (before any network
	// use) and gives the effective output settings.
	cfg, err := authdiff.LoadConfig(opts.ConfigPath, opts.Overrides)
	if err != nil {
		return err
	}
	if err := checkFormats(cfg.Output.Formats); err != nil {
		return err
	}
	a.log.Debug("config loaded", "path", opts.ConfigPath, "target", authdiff.RedactURL(cfg.Target.BaseURL),
		"profiles", cfg.ProfileNames(), "formats", cfg.Output.Formats, "dir", cfg.Output.Dir,
		"rate", cfg.Safety.Rate, "concurrency", cfg.Safety.Concurrency,
		"allowDestructive", cfg.Safety.AllowDestructive)

	res, scanErr := authdiff.Scan(ctx, opts)
	if res == nil {
		return scanErr
	}
	paths, werr := report.Write(cfg.Output.Dir, cfg.Output.Formats, res, a.stdout, a.color())
	for _, p := range paths {
		a.log.Info("report written", "path", p)
	}
	if werr != nil {
		return errors.Join(scanErr, werr)
	}
	if scanErr != nil {
		if errors.Is(scanErr, context.Canceled) {
			fmt.Fprintln(a.stderr, "scan interrupted, partial results written")
			return &codeError{code: exitError}
		}
		return scanErr
	}
	if responses := res.Stats.Requests - res.Stats.Blocked - res.Stats.Errors; responses <= 0 {
		return &codeError{code: exitError, err: fmt.Errorf(
			"no request received an HTTP response (%d requests, %d blocked, %d errors): nothing was tested; "+
				"check target.baseUrl, scope.allowHosts, the network and safety.timeout",
			res.Stats.Requests, res.Stats.Blocked, res.Stats.Errors)}
	}
	if cfg.Output.FailOn == "" {
		return nil
	}
	sev, err := finding.ParseSeverity(cfg.Output.FailOn)
	if err != nil {
		return err
	}
	if res.FailsAt(sev) {
		return &codeError{code: exitFailOn, err: fmt.Errorf("active findings at or above %s severity (fail-on)", sev)}
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
