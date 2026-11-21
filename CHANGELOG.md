# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `authdiff` CLI with `init`, `inventory`, `scan` (including `--dry-run`),
  `rules list` / `rules validate`, `report` and `version`.
- Public Go API `pkg/authdiff` (`Scan`, `PlanContext`, `LoadConfig`,
  `LoadInventory`, `LoadRules`).
- OpenAPI 3.0 / 3.1 inventory (YAML or JSON, file or URL) with parameter and
  body example generation, `include` / `exclude` / tag filters.
- Profiles with bearer, cookie, API key, basic and anonymous authentication;
  `${env:NAME}` secrets; owned IDs and automatic ID harvesting.
- Built-in rules: AD-BOLA-001, AD-BOLA-002, AD-BFLA-001, AD-NOAUTH-001,
  AD-MASS-001, AD-METHOD-001, AD-MATRIX-001, AD-LEAK-001; custom YAML rule
  templates with `expr` conditions.
- Structural JSON similarity with dynamic field detection, anonymous baseline
  and ownership evidence for confidence.
- Safety controls in the transport: mandatory host allow-list (redirects and
  spec download included), authorization acknowledgement, rate limit
  (default 5 req/s), safe mode for `DELETE`/`PUT`/`PATCH`, TLS verification,
  5 MB response limit, retries with backoff, self-identifying User-Agent.
- Reports: terminal, JSON, SARIF 2.1.0 and single-file HTML with an
  endpoint × profile heat map; secrets masked in every output.
- Stable finding IDs, `.authdiff-ignore` baseline and `--fail-on` exit codes.
- vuln-lab: deliberately vulnerable FastAPI demo with a machine-readable list
  of expected findings, and an end-to-end test against it.
- GitHub Action (`action/`), CI, E2E, CodeQL and release workflows,
  GoReleaser builds for linux/darwin/windows × amd64/arm64 with checksums, and
  a distroless Docker image `ghcr.io/ardayesilcayir/authdiff`.
- Documentation: README (English and Turkish), configuration reference, rule
  writing guide, rule reference, architecture and ADRs.

### Safety

- Destructive probes: the AD-NOAUTH-001 reference step never sends
  `DELETE`/`PUT`/`PATCH`; a destructive request whose path IDs no configured
  profile owns is skipped; method swap never probes as an admin and never
  sends destructive methods to collection paths; the `DELETE` phase runs
  sequentially; mass assignment no longer tests admin profiles.
- Redirects from `https` to `http` or to a different `host:port` are refused,
  so `Authorization`, cookies and custom API key headers are never forwarded.
- `HTTP_PROXY` / `HTTPS_PROXY` are ignored; a proxy is used only when set
  with the new `safety.proxy` key or `--proxy` flag, and is logged.
- Network errors are retried only for `GET`/`HEAD`/`OPTIONS`; `429`/`503`
  are still retried for any method.
- Resource limits against hostile targets and specs: JSON flattening keeps
  at most 50,000 leaves (marked `<leaf-limit>`) and truncates keys longer
  than 256 characters; `safety.maxResponseBytes` is capped at 50 MiB; spec
  example generation is memoised with a 10,000-node budget per endpoint;
  source lines are indexed in one pass; a spec larger than 10 MiB is an
  error instead of being silently truncated.
- `--insecure` logs a warning and adds a "TLS verification disabled" note to
  the terminal, JSON and HTML reports.

### Fixed

- A scan in which no request received an HTTP response exits `2` with an
  error instead of reporting "No findings."; the terminal summary and HTML
  report show blocked requests and errors, and every authenticated profile
  that never got a `2xx` is logged as a warning.
- Waiting for the rate limiter no longer counts against `safety.timeout`, so
  low `--rate` values do not cause spurious timeouts; blocked requests never
  consume a rate-limit token.
