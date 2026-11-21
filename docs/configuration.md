# Configuration reference

authdiff reads one YAML file, `authdiff.yaml` by default (`-c` / `--config`
selects another). `authdiff init` writes a commented starting point, and
[`examples/authdiff.yaml`](../examples/authdiff.yaml) is a complete config for
the bundled vuln-lab.

```yaml
version: 1
target:
  baseUrl: http://localhost:8000
  spec: ./openapi.json

scope:
  allowHosts: ["localhost:8000"]
  acknowledgeAuthorization: true

safety:
  rate: 5
  concurrency: 4
  allowDestructive: false
  timeout: 10s

profiles:
  admin:
    role: admin
    auth: { type: bearer, token: "${env:ADMIN_TOKEN}" }
  alice:
    role: user
    auth: { type: bearer, token: "${env:ALICE_TOKEN}" }
    owns: { userId: [2], orderId: [101, 102], invoiceId: [9001] }
    identifiers: [alice@vuln.lab]
  bob:
    role: user
    auth: { type: bearer, token: "${env:BOB_TOKEN}" }
    owns: { userId: [3], orderId: [201] }
  anonymous:
    role: none
    auth: { type: none }

harvest:
  - endpoint: GET /me/orders
    extract: { orderId: "$.items[*].id" }

matrix:
  "GET /admin/**":         { allow: [admin] }
  "GET /orders/{orderId}": { allow: [admin, owner] }

compare:
  ignoreFields: ["$.requestId", "$..updatedAt"]
  similarityThreshold: 0.85

output:
  formats: [terminal, json, sarif, html]
  dir: ./authdiff-out
  failOn: high
```

All problems in a config are reported together, each naming its field. A
config error exits with code `2` before any request is sent.

## Secrets: `${env:NAME}`

Any value can reference an environment variable as `${env:NAME}`. The
substitution happens before YAML parsing. An unset variable is an error that
names the variable. Never write tokens into the file itself.

Every token and password from `profiles` is masked in every output (terminal,
logs, JSON, SARIF, HTML) as `****` plus its last 4 characters (`****` only for
values shorter than 8 characters). For `basic` auth the user name (when it
has at least 4 characters) and the base64 `username:password` credential are
masked too. JWT-shaped strings (`eyJ….….…`) in evidence are masked even when
the target issued them. The `Authorization`, `Cookie`, `Set-Cookie` and
`X-API-Key` headers are always masked the same way. Configuration errors
never show a value substituted from `${env:NAME}`.

Unknown keys are errors (`field allowDestructve not found`), so a typo in a
safety setting cannot silently fall back to its default.

**Reports are sensitive.** Evidence contains the target's response bodies
(other users' data, for a real finding). Report directories are created
owner-only (`0700`) and files `0600`; an existing symlink in place of a report
file is refused. `authdiff init` writes `authdiff.yaml` as `0600`.

## `version`

Must be `1`.

## `target`

| Key | Required | Description |
|---|---|---|
| `baseUrl` | yes | Absolute URL the API is served from, without credentials (`user:pass@` is rejected: it would be sent by the anonymous probe too; use a profile's `auth`). A path prefix is kept: `http://h/api` + `/orders/{orderId}` becomes `http://h/api/orders/101`. |
| `spec` | yes | OpenAPI 3.0 or 3.1 document, YAML or JSON. A file path (relative to the config file) or an `http(s)` URL. A URL is downloaded through the same scoped transport as every other request, so it must be inside `allowHosts`. A spec larger than 10 MiB is rejected. |

Use a local spec file when you upload SARIF to GitHub code scanning: SARIF
locations point at the spec file, and code scanning needs a file in the
repository.

## `scope` (required)

| Key | Description |
|---|---|
| `allowHosts` | Hosts (`host` or `host:port`) authdiff may contact. Matching is case-insensitive; a missing port means the scheme default (`example.com` matches `https://example.com:443`). Subdomains are **not** included: `example.com` does not allow `api.example.com` or `example.com.evil.io`. Redirects are checked too. |
| `acknowledgeAuthorization` | Must be `true`. It is your statement that you own the system or have written permission to test it. |

A scan does not start when `allowHosts` is empty, when
`acknowledgeAuthorization` is not `true`, or when `allowHosts` does not
include the `baseUrl` host.

## `safety`

| Key | Default | Description |
|---|---|---|
| `rate` | `5` | Maximum requests per second, across all workers. CLI: `--rate`. |
| `concurrency` | `4` | Endpoints tested in parallel. CLI: `--concurrency`. |
| `allowDestructive` | `false` | `DELETE`, `PUT` and `PATCH` are blocked unless `true`. Blocked requests are counted in the stats. CLI: `--allow-destructive`. Even when `true`, a destructive request is sent only when every path ID belongs to a configured profile (`owns` or harvest); others are skipped. |
| `timeout` | `10s` | Per-attempt request timeout (Go duration). Time spent waiting for the rate limiter is not counted. |
| `maxResponseBytes` | `5242880` (5 MB) | Larger responses are truncated and marked `truncated` in evidence. At most `52428800` (50 MiB). JSON comparison looks at no more than 50,000 leaves per response and truncates object keys longer than 256 characters. |
| `insecure` | `false` | Skip TLS certificate verification. Logged as a warning and shown in every report. CLI: `--insecure`. |
| `proxy` | none | Explicit proxy URL (`http`, `https` or `socks5`) for every request. `HTTP_PROXY` / `HTTPS_PROXY` are ignored. The proxy sees all traffic, credentials included, and is not checked against `allowHosts`; its use is logged at start. CLI: `--proxy`. |

**Safe mode still sends `POST`.** `POST` is not blocked: mass assignment
(`AD-MASS-001`), method swap (`AD-METHOD-001`) and template rules on `POST`
operations send real `POST` requests that **create objects** on the target,
even without `allowDestructive`. Use a test environment you can reset, or
exclude those operations with `filter.exclude`.

`429`/`503` responses are retried up to 3 times with exponential backoff, for
any method. Network errors are retried the same way only for `GET`, `HEAD`
and `OPTIONS`: a write may have been processed before the connection broke.

Redirects are followed (at most 5) only within the original `host:port` and
never from `https` to `http`; other redirects are refused and recorded as
errors, so credentials are never forwarded.

## `profiles` (at least one)

Each key is a profile name used in findings (`bob→alice`).

| Key | Description |
|---|---|
| `role` | Free-form role name. `admin` marks the admin profile; profiles with the same role are paired for BOLA (owner versus other user). The anonymous profile is the one with `auth.type: none`. |
| `auth` | How the profile authenticates (see below). |
| `owns` | IDs of objects this profile owns, per path parameter name: `{ orderId: [101, 102] }`. They are substituted into `{orderId}` path parameters. |
| `identifiers` | Strings that identify this profile in a response body (e-mail, username). The profile's owned `userId` values are added automatically. Seen in another profile's response, they raise the confidence of a finding to `high`. |

Auth types:

| `type` | Fields | Sent as |
|---|---|---|
| `bearer` | `token` | `Authorization: Bearer <token>` |
| `cookie` | `token`, optional `name` | `Cookie: <name>=<token>`, or `Cookie: <token>` without `name` |
| `apikey` | `token`, optional `name`, `in: header\|query` | header `X-API-Key` (default name) or query parameter `api_key` (default name) |
| `basic` | `username`, `password` | HTTP Basic |
| `none` | none | no credentials |

A typical setup has an admin, two users with the same role, and an anonymous
profile. Without two users of the same role, BOLA cannot be tested.

## `harvest`

Collects more owned IDs from each profile's own responses before testing.
Every non-anonymous profile calls each harvest endpoint; extracted values are
added to that profile's `owns`.

```yaml
harvest:
  - endpoint: GET /me/orders               # METHOD /path (destructive methods are never used)
    extract: { orderId: "$.items[*].id" }  # path parameter name -> JSONPath
```

Failures are logged and skipped. A harvest endpoint must be in the inventory
after `filter` / `--include` / `--exclude` / `--tag`; otherwise it is skipped,
so filters also limit harvest traffic. `--dry-run` does not run harvest, so
its plan only uses configured `owns`.

## `matrix`

The expected authorization policy. Keys are endpoint globs with an optional
method prefix (`*` = one path segment, `**` = any number). Values list who is
allowed: profile names, roles, `owner` (the profile requests its own
objects) or `anonymous`.

```yaml
matrix:
  "GET /admin/**":         { allow: [admin] }
  "GET /orders/{orderId}": { allow: [admin, owner] }
  "POST /orders":          { allow: [admin, user] }
```

Every 2xx response that the matrix does not allow becomes an
[AD-MATRIX-001](rules/AD-MATRIX-001.md) finding. An entry that allows only
`admin` also marks the endpoint as an admin function for
[AD-BFLA-001](rules/AD-BFLA-001.md). The matrix is optional: without it,
authdiff infers problems by comparing owners with other users.

## `compare`

| Key | Default | Description |
|---|---|---|
| `ignoreFields` | none | JSONPath-like paths excluded from similarity (`$.requestId`, `$..updatedAt` for any depth). Fields that change between two identical owner requests are ignored automatically. |
| `similarityThreshold` | `0.85` | Minimum structural similarity (0 to 1) for "the attacker got the same data". |

## `bodies`

Request bodies by endpoint, used instead of the spec's examples when the
generated body is not accepted:

```yaml
bodies:
  "POST /orders": { productId: 1, quantity: 2 }
  "PATCH /orders/{orderId}": { status: "cancelled" }
```

## `filter`

| Key | CLI | Description |
|---|---|---|
| `include` | `--include` | Only test endpoints matching one of these globs (`/orders/**`, `GET /admin/*`). |
| `exclude` | `--exclude` | Skip matching endpoints. |
| `tags` | `--tag` | Only test operations with one of these OpenAPI tags. |

No request is sent to a filtered-out endpoint.

## `rules`

| Key | CLI | Description |
|---|---|---|
| `dirs` | `--rules` | Directories of custom rule templates (relative to the config file). See [writing-rules.md](writing-rules.md). |
| `disable` | none | Rule IDs to skip, built-in or custom. An unknown ID is an error. |

## `output`

| Key | Default | CLI | Description |
|---|---|---|---|
| `formats` | `[terminal, json]` | `--format` | Any of `terminal`, `json` (`results.json`), `sarif` (`results.sarif`), `html` (`report.html`). |
| `dir` | `./authdiff-out` | `-o`, `--output` | Report directory (relative to the working directory). |
| `failOn` | none | `--fail-on` | Exit `1` when an active (not suppressed) finding has at least this severity: `info`, `low`, `medium`, `high`, `critical`. |

## Suppressing findings: `.authdiff-ignore`

One 12-character finding ID per line, with an optional `# comment`. The ID is
stable: it is derived from rule, method, path, victim and attacker. Suppressed
findings stay in the reports, marked as suppressed, and do not count toward
`failOn`. Use `--ignore-file` for another path.

```
3f9a1c0b7d2e  # AD-BOLA-001 GET /orders/{orderId} alice -> bob: shared by design
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished, no active finding at or above `failOn` |
| `1` | At least one active finding at or above `failOn` |
| `2` | Configuration, usage or runtime error, or a scan in which no request received an HTTP response (every request blocked or failed: nothing was tested) |
