# Architecture

authdiff is a one-way pipeline: inputs become a request plan, every request
passes the safety layers of the transport, responses are compared, and
findings are reported from a single data model.

```
 authdiff.yaml ──► config ──┐                                   ┌──► terminal
 (env expansion,            │                                   ├──► results.json
  validation)               ▼                                   ├──► results.sarif
                         engine ──► planner ──► transport ──► target API
 OpenAPI spec ──► spec ─────▲          ▲      (scope → safe mode → rate limit
 (inventory, filter)        │          │       → retries → record + mask)
                            │       identity                    │
 rules/*.yaml ──► rules ────┘   (profiles, auth,                ▼
 (templates, expr)               owned-ID pool)            compare ──► finding ──► report
                                                         (similarity,  (ID, severity,  └──► report.html
                                                          evidence)     baseline)
```

The CLI (`internal/cli`, cobra) is a thin layer over the public package
`pkg/authdiff`, which loads the config, spec and rules, runs the engine and
applies the ignore baseline. Embedding authdiff in another Go program uses the
same entry point:

```go
res, err := authdiff.Scan(ctx, authdiff.ScanOptions{ConfigPath: "authdiff.yaml"})
```

## Packages

| Package | Responsibility |
|---|---|
| `pkg/authdiff` | Public API: `Scan`, `PlanContext`, `LoadConfig`, `LoadInventory`, `LoadRules`. Resolves relative paths against the config file and redacts URL secrets in errors. |
| `internal/cli` | Commands `init`, `inventory`, `scan`, `rules`, `report`, `version`; flags, logging (`slog`, text or JSON), exit codes. The only package that imports cobra. |
| `internal/config` | `authdiff.yaml` model, `${env:NAME}` expansion, defaults, validation that reports every problem at once. |
| `internal/spec` | OpenAPI 3.0/3.1 loading (kin-openapi), endpoint inventory with parameters, request body examples, `security`, tags and source line; glob filters. |
| `internal/identity` | Profiles, credential injection (bearer, cookie, API key, basic, none), the pool of owned IDs per profile (config plus harvest). |
| `internal/planner` | Builds concrete requests: fills path parameters from the pool, generates bodies from examples or `bodies`. |
| `internal/transport` | The only package that touches the network (see below). |
| `internal/compare` | JSON flattening, structural similarity, ownership evidence. |
| `internal/rules` | Loads and validates YAML rule templates, compiles and evaluates `expr` expressions. |
| `internal/engine` | Check registry (template, mass assignment, method swap, leak, matrix), harvest, phased runner, access matrix. |
| `internal/finding` | Finding, Result, severity, stable IDs, `.authdiff-ignore` baseline. |
| `internal/report` | Terminal, JSON, SARIF 2.1.0 and HTML writers. Imports only `finding`. |
| `rules/` | Built-in rule templates, embedded into the binary. |

## The transport: safety in one place

Detection code never creates its own HTTP client. It receives a
`transport.Client` whose `RoundTripper` chain is, from the outside in:

1. **Scope**: the request's normalized `host:port` must be in
   `scope.allowHosts`. Redirects are re-sent through the chain, so a redirect
   out of scope is refused as well.
2. **Safe mode**: `DELETE`, `PUT` and `PATCH` are refused unless
   `allowDestructive` is set. Refusals are counted as blocked.
3. **Rate limit**: a token bucket shared by all workers (default 5 requests per
   second).
4. **Base transport** with TLS verification on (unless `--insecure`), a
   per-request timeout and a response size limit (5 MB, larger bodies are
   truncated and flagged).

Around the chain, the client retries network errors and `429`/`503` up to 3
times with exponential backoff, sets the `User-Agent`
`authdiff/<version> (+https://github.com/ardayesilcayir/authdiff)` and records
each exchange with secrets masked. Because these controls live below the
engine, a new rule, built-in or custom, cannot bypass them. Even the spec
download for a URL `target.spec` goes through this client.

## Scan flow

1. **Load**: config (env expansion, defaults, validation), spec inventory
   (filtered by `include`/`exclude`/`tags`), rules (built-in plus `rules.dirs`
   minus `rules.disable`), baseline.
2. **Harvest**: every non-anonymous profile calls the `harvest` endpoints; the
   extracted IDs join its pool. Destructive methods are never used here.
3. **Phases**: checks run in phases by method so reads see data before it is
   changed: `GET`/`POST` and other safe checks, then `PUT`/`PATCH` (and mass
   assignment), then method swap probes, then `DELETE`. Within a phase up to
   `safety.concurrency` endpoints are in flight; the checks of one endpoint run
   sequentially on the same worker.
4. **Checks**: a template check enumerates role bindings (owner, other user,
   admin, ...), sends its steps, and evaluates the rule's `match` and
   `confidence` expressions with the responses. Built-in Go checks handle mass
   assignment, method swap and sensitive data exposure.
5. **Matrix**: after all phases, every observed 2xx is compared with the
   `matrix` (AD-MATRIX-001), and the endpoint × profile access matrix is built
   for the HTML heat map.
6. **Result**: findings are de-duplicated by ID (highest confidence kept),
   sorted deterministically, and marked suppressed by the baseline. Reports are
   written from this single result; `authdiff report` can re-render a saved
   `results.json`.

Probe, build and evaluation errors are logged and counted; they skip one
combination, never the whole scan. Cancelling (Ctrl-C) returns the partial
result, so reports can still be written.

## Comparison algorithm

The BOLA decision (owner twice, attacker, anonymous baseline, structural
similarity with dynamic field masking, identifier evidence for confidence) is
described in [ADR-0002](adr/0002-karsilastirma-algoritmasi.md) and per rule in
[docs/rules](rules/).

## Findings and outputs

A finding carries rule, OWASP and CWE classification, severity with a CVSS 3.1
estimate, confidence, method and path template, victim and attacker profiles,
similarity, masked request/response evidence, and remediation. Its ID is the
first 12 hex characters of `sha256(rule|method|path|victim|attacker)`, so it
is stable across runs and usable in `.authdiff-ignore`.

| Output | For | Content |
|---|---|---|
| terminal | the person running the scan | findings by severity, request count, duration |
| `results.json` | automation, `authdiff report` | the full result |
| `results.sarif` | GitHub code scanning | rules and results; location = the operation's line in the spec file |
| `report.html` | readers of the report | single file with a CSP, summary, endpoint × profile heat map, evidence and remediation per finding; all target content escaped by `html/template` |

## Design decisions

- [ADR-0001: Go as the implementation language](adr/0001-go-secimi.md)
- [ADR-0002: Response comparison algorithm](adr/0002-karsilastirma-algoritmasi.md)
