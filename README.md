# authdiff

[![CI](https://github.com/ardayesilcayir/authdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/ardayesilcayir/authdiff/actions/workflows/ci.yml)
[![E2E](https://github.com/ardayesilcayir/authdiff/actions/workflows/e2e.yml/badge.svg)](https://github.com/ardayesilcayir/authdiff/actions/workflows/e2e.yml)
[![CodeQL](https://github.com/ardayesilcayir/authdiff/actions/workflows/codeql.yml/badge.svg)](https://github.com/ardayesilcayir/authdiff/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**authdiff finds authorization bugs in REST APIs**: broken object level
authorization (BOLA/IDOR), broken function level authorization (BFLA),
missing authentication and mass assignment. Give it your OpenAPI spec and a
few identities (admin, two users, anonymous). It calls every endpoint as
every identity, compares the responses, and reports who could access what
they should not, with masked request/response evidence, in the terminal,
JSON, SARIF and HTML.

[Türkçe README](README.tr.md)

```
SEVERITY  RULE           ENDPOINT                       ATTACKER→VICTIM  CONF
────────  ─────────────  ─────────────────────────────  ───────────────  ──────
HIGH      AD-BFLA-001    GET /admin/users               alice→admin      high
HIGH      AD-BOLA-001    GET /invoices/{invoiceId}/pdf  bob→alice        high
HIGH      AD-BOLA-001    GET /orders/{orderId}          bob→alice        high
HIGH      AD-NOAUTH-001  GET /users/{userId}/profile    anonymous→admin  high
MEDIUM    AD-LEAK-001    GET /users/{userId}            admin→admin      medium
```

## Why

An authorization bug has no signature: `GET /orders/42` is a perfectly valid
request, it is only wrong when the caller does not own order 42. Generic
scanners run with a single session and never ask "A can see this, should B?".
Proxy plugins answer that question by hand and do not run in CI. authdiff
turns it into a repeatable, CI-friendly test generated from your OpenAPI
spec. The three authorization classes it targets are API1 (BOLA), API3
(object property level, including mass assignment) and API5 (BFLA) of the
[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

## Quick start: first results in 5 minutes

You need Go 1.23+ and Docker. The bundled [vuln-lab](vuln-lab/) is a small,
deliberately vulnerable shop API that runs on `127.0.0.1:8000` only.

```sh
git clone https://github.com/ardayesilcayir/authdiff && cd authdiff
go install ./cmd/authdiff            # or: make build (writes dist/authdiff)

make lab                             # start the vuln-lab (Docker), wait until healthy

set -a; source examples/vuln-lab.env; set +a   # export the lab's FAKE tokens
authdiff scan -c examples/authdiff.yaml
```

The scan prints the findings above and writes `authdiff-out/results.json`,
`results.sarif` and `report.html`. Open `report.html` for the evidence and the
endpoint × profile heat map. The exit code is `1` because findings reached
`failOn: high`.

By default destructive methods (`DELETE`, `PUT`, `PATCH`) are blocked. To find
the write-side bugs as well (BOLA on `PATCH`, admin `DELETE`, mass
assignment), allow them and restart the lab afterwards, because those checks
change its data:

```sh
authdiff scan -c examples/authdiff.yaml --allow-destructive
make lab-restart                     # the lab reseeds on every start
```

PowerShell instead of `set -a; source ...`:

```powershell
Get-Content examples/vuln-lab.env | Where-Object { $_ -match '^[A-Z_]+=' } |
  ForEach-Object { $k, $v = $_ -split '=', 2; Set-Item "env:$k" $v }
```

Without Docker: `cd vuln-lab && python -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000`.

## Install

| Method | Command |
|---|---|
| Go | `go install github.com/ardayesilcayir/authdiff/cmd/authdiff@latest` |
| Release binary | Linux, macOS, Windows × amd64, arm64 from [Releases](https://github.com/ardayesilcayir/authdiff/releases), with `checksums.txt` |
| Docker | `docker run --rm -v "$PWD:/work" -e ALICE_TOKEN ghcr.io/ardayesilcayir/authdiff scan -c authdiff.yaml` |
| GitHub Action | `uses: ardayesilcayir/authdiff/action@v1` (see [CI usage](#ci-usage)) |

## Features

| Area | What authdiff does |
|---|---|
| Input | OpenAPI 3.0 / 3.1, YAML or JSON, file or URL; path, query, header and body parameters filled from examples; `--include` / `--exclude` / `--tag` filters |
| Identities | Any number of profiles: bearer, cookie, API key (header or query), basic, anonymous; secrets from `${env:NAME}` |
| Ownership | `owns` per profile, automatic ID harvesting from the profile's own responses, optional authorization `matrix` |
| BOLA | Read ([AD-BOLA-001](docs/rules/AD-BOLA-001.md)) and write ([AD-BOLA-002](docs/rules/AD-BOLA-002.md)): another user with the owner's IDs |
| BFLA | Admin functions called by low-privileged users ([AD-BFLA-001](docs/rules/AD-BFLA-001.md)) |
| Missing auth | Protected endpoints answering anonymous requests ([AD-NOAUTH-001](docs/rules/AD-NOAUTH-001.md)) |
| Mass assignment | `role`, `isAdmin`, `ownerId` injected and read back ([AD-MASS-001](docs/rules/AD-MASS-001.md)) |
| Method swap | Undocumented methods without authorization ([AD-METHOD-001](docs/rules/AD-METHOD-001.md)) |
| Matrix | Observed access versus your declared policy ([AD-MATRIX-001](docs/rules/AD-MATRIX-001.md)) |
| Data exposure | Sensitive fields outside the response schema ([AD-LEAK-001](docs/rules/AD-LEAK-001.md)) |
| Comparison | Structural JSON similarity, dynamic fields learnt by repeating the owner request, anonymous baseline against public data, identifier evidence for confidence |
| Custom rules | YAML templates with `expr` conditions, no Go code ([docs/writing-rules.md](docs/writing-rules.md)) |
| Safety | Mandatory host allow-list (redirects included), authorization acknowledgement, 5 req/s default, destructive methods off, TLS verification on, 5 MB response limit, `--dry-run` |
| Output | Terminal table, JSON, SARIF 2.1.0 (GitHub code scanning), single-file HTML report with heat map; tokens masked everywhere |
| Workflow | Stable finding IDs, `.authdiff-ignore` baseline, `--fail-on` exit codes, `authdiff report` to re-render saved results |

## Usage

| Command | What it does |
|---|---|
| `authdiff init` | Writes a commented `authdiff.yaml` and `.authdiff-ignore` |
| `authdiff inventory -c authdiff.yaml` | Lists the endpoints from the spec; sends no requests (only downloads a URL spec) |
| `authdiff scan -c authdiff.yaml` | Runs the scan |
| `authdiff scan --dry-run` | Prints the request plan as a table, sends nothing to the target |
| `authdiff rules list` / `rules validate <file>` | Lists rules / validates a custom rule |
| `authdiff report -i results.json -f html` | Renders a saved result in another format |
| `authdiff version` | Version, commit and build date |

Common `scan` flags: `--rate 5`, `--concurrency 4`, `--allow-destructive`,
`--fail-on high`, `--format terminal,json,sarif,html`, `--output ./out`,
`--include "/orders/**"`, `--rules ./rules`, `--ignore-file`, `--insecure`.
Global: `-v`, `--log-format json`, `--no-color`.

Exit codes: `0` no active finding at the `--fail-on` threshold, `1` threshold
reached, `2` error.

A minimal config:

```yaml
version: 1
target:
  baseUrl: https://staging.example.com
  spec: ./openapi.yaml
scope:
  allowHosts: ["staging.example.com"]
  acknowledgeAuthorization: true     # you are authorized to test this system
profiles:
  alice: { role: user, auth: { type: bearer, token: "${env:ALICE_TOKEN}" }, owns: { orderId: [101] } }
  bob:   { role: user, auth: { type: bearer, token: "${env:BOB_TOKEN}" },   owns: { orderId: [201] } }
  anonymous: { role: none, auth: { type: none } }
```

Every option is described in [docs/configuration.md](docs/configuration.md).

## CI usage

The composite GitHub Action installs authdiff, runs the scan, uploads the
SARIF to code scanning (findings appear under **Security → Code scanning**)
and fails the job at the `fail-on` threshold:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  authz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ardayesilcayir/authdiff/action@v1
        with:
          config: authdiff.yaml      # required
          version: v1.0.0            # default: latest
          fail-on: high              # default: high
          upload-sarif: "true"       # default: true
        env:
          ALICE_TOKEN: ${{ secrets.AUTHDIFF_ALICE_TOKEN }}
          BOB_TOKEN: ${{ secrets.AUTHDIFF_BOB_TOKEN }}
```

A complete workflow is in [examples/workflow.yml](examples/workflow.yml). Use
a spec file from the repository (`target.spec: ./openapi.yaml`) so SARIF
results point at the operation's line. Point CI at a staging or test
environment, never at production, and keep destructive checks off unless the
environment is reset after each run.

Other CI systems: run the binary or the Docker image and use the exit code;
`results.sarif` and `results.json` are standard files.

## Ethical use

authdiff is built for systems **you own or have written permission to
test**. Unauthorized access to computer systems is a crime in most countries;
in Türkiye it falls under Articles 243 and 244 of the Turkish Penal Code (TCK
243–244: unlawful access to an information system, and hindering, disrupting
or altering data). You are responsible for how you use this tool.

The safety defaults are "off" and stay that way unless you change them:

- No scan without `scope.allowHosts` and `acknowledgeAuthorization: true`.
- No request outside `allowHosts`, redirects included; the spec download is
  checked too.
- 5 requests per second by default; `DELETE`, `PUT` and `PATCH` blocked
  unless `--allow-destructive`.
- A self-identifying `User-Agent: authdiff/<version>
  (+https://github.com/ardayesilcayir/authdiff)`, so system owners can
  recognize the traffic.
- No brute force, credential guessing or denial-of-service features, by
  design.
- Tokens are masked in logs and every report; the HTML report escapes target
  content and ships a Content Security Policy; TLS verification is on by
  default.

For bug bounty programs, read the program's scope and rules first, use a low
`--rate`, and test only with accounts you control.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Writing rules](docs/writing-rules.md)
- [Rule reference](docs/rules/): what each rule finds, how it works, how to fix it
- [Architecture](docs/architecture.md) and decisions: [ADR-0001 Go](docs/adr/0001-go-secimi.md), [ADR-0002 comparison algorithm](docs/adr/0002-karsilastirma-algoritmasi.md)
- [vuln-lab](vuln-lab/README.md) and its [expected findings](vuln-lab/VULNERABILITIES.md)

## Development

```sh
go test ./...                 # unit, engine and golden tests
make cover                    # internal/ coverage (CI requires >= 80%)
make lint                     # golangci-lint
make e2e                      # recreates the vuln-lab, then the end-to-end test
```

The end-to-end test runs a destructive scan against a fresh vuln-lab and
requires the found `(rule, method, path)` set to equal the oracle in
[VULNERABILITIES.md](vuln-lab/VULNERABILITIES.md), with no finding on the
negative controls. It logs recall and false positive rate (currently 1.00 and
0.00). The lab keeps its data in memory and reseeds on start; `make e2e`
recreates the container first, because a previous destructive scan changes
the data.

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues in authdiff itself:
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
