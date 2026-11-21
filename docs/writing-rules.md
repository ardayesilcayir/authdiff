# Writing rules

A rule is a YAML template: which endpoints it applies to, which requests to
send as which identities, and an expression that decides whether the
responses are a finding. Custom rules need no Go code and run through the same
transport as the built-in ones, so scope, rate limit, safe mode and masking
apply to them as well.

```sh
authdiff rules validate ./rules/my-rule.yaml     # check one file: prints "OK <id>"
authdiff rules list --rules ./rules              # built-in + custom rules
authdiff scan -c authdiff.yaml --rules ./rules   # or rules.dirs in the config
```

Every `*.yaml` / `*.yml` file in a rules directory is loaded. A rule ID that
is defined twice (also against a built-in rule) is an error.

## A complete example

The built-in BOLA read rule, [`rules/bola-read.yaml`](../rules/bola-read.yaml):

```yaml
id: AD-BOLA-001
name: Broken object level authorization (read)
owasp: "API1:2023"
cwe: CWE-639
severity: high
description: >
  A user can read an object owned by another user by supplying its identifier.
remediation: docs/rules/AD-BOLA-001.md
applies:
  methods: [GET]
  pathHasParam: true
  adminFunction: false
steps:
  - name: owner          # the owner reads its own object, twice (dynamic fields)
    as: owner
    use: owner
    repeat: 2
  - name: attacker       # another user of the same role, with the owner's IDs
    as: other_user
    use: owner
  - name: anon           # anonymous baseline: public data is not BOLA
    as: anonymous
    use: owner
victim: owner
attacker: attacker
match: >
  owner.ok && len(owner.body) > 0 && attacker.ok &&
  !(anon.ok && similarity(owner.body, anon.body) >= cfg.similarityThreshold) &&
  similarity(owner.body, attacker.body) >= cfg.similarityThreshold
confidence:
  high: evidence(attacker.body, owner.identifiers)
  medium: "true"
```

## Fields

| Field | Required | Description |
|---|---|---|
| `id` | yes | Uppercase, dash-separated: `^[A-Z]+(-[A-Z0-9]+)+$`, for example `ACME-TENANT-001`. Keep the `AD-` prefix for built-in rules. |
| `name` | yes | Short title shown in reports. |
| `severity` | yes | `info`, `low`, `medium`, `high` or `critical`. |
| `cvss` | no | CVSS 3.1 base score estimate. Default by severity: critical 9.1, high 8.1, medium 6.5, low 3.7, info 0. |
| `owasp`, `cwe` | no | Classification shown in reports and SARIF. |
| `description` | no | What the finding means. |
| `remediation` | no | How to fix it: a sentence or a link. |
| `applies` | no | Endpoint filter (below). Without it the rule runs on every endpoint. |
| `steps` | yes | Requests to send (below). |
| `match` | yes | Boolean expression: true means finding. |
| `victim`, `attacker` | no | Step names whose profiles are reported as victim and attacker. Defaults: first and last step. |
| `confidence` | no | `high`, `medium`, `low` expressions, tried in that order; the first true one wins. Default `medium`. |
| `kind` | no | `template` (default). `massassign`, `methodswap`, `leak` and `matrix` select built-in Go checks and are only meant for the built-in rules. |

### `applies`

| Key | Meaning |
|---|---|
| `methods` | Only these HTTP methods. |
| `pathHasParam` | `true`: only paths with a `{param}`; `false`: only paths without one. |
| `adminFunction` | `true`: only admin functions (a path segment or tag `admin`, or a matrix entry that allows only `admin`); `false`: only other endpoints. |
| `paths` | Only paths matching one of these globs (`/orders/**`). |
| `requiresBody` | Only operations with a request body. |

### `steps`

Steps run in order for every **binding**: every combination of profiles that
can fill the roles the rule uses. A BOLA rule on a lab with alice and bob (both
`role: user`) runs twice: alice as owner and bob as other user, then the other
way round.

| Key | Description |
|---|---|
| `name` | Lowercase identifier (`^[a-z_][a-z0-9_]*$`), used in expressions. Must be unique and not one of `endpoint`, `cfg`, `identifiers`, `similarity`, `evidence`, `matrixForbids`, `matrixAllows`, `len`. |
| `as` | Role that sends the request (table below). |
| `use` | Role whose owned IDs fill the path parameters. |
| `method` | Send this method instead of the endpoint's (for example a `GET` before a write). |
| `repeat` | Send the request this many times (at most 10). Fields that differ between repeats are marked dynamic and ignored by `similarity`. |
| `skipDestructive` | Do not send the step when its method is `DELETE`, `PUT` or `PATCH`; `name.sent` is then `false`. |
| `body` | Top-level JSON keys merged into the request body. |

Roles:

| Role | Bound to |
|---|---|
| `owner` | each profile that owns an ID for every path parameter |
| `other_user` | each other profile with the owner's role (with no `owner` in the rule: any profile other than `self`) |
| `self` | each non-anonymous profile |
| `low_priv` | each non-admin, non-anonymous profile |
| `admin` | the first profile with `role: admin` |
| `anonymous` | the profile with `auth.type: none` |
| `any_user` | one non-anonymous profile, preferably one that owns the path IDs |

`{{owner}}` and `{{owner.owns}}` are accepted as spellings of `owner`. A step
whose role has no profile is not sent. Destructive methods still need
`--allow-destructive`; without it the transport blocks the request and the
step is not sent.

## Expressions

`match` and `confidence` use [expr](https://expr-lang.org/) syntax (`&&`,
`||`, `!`, comparisons, `in`, `len()`). Expressions are compiled when the rule
is loaded, so typos fail `rules validate`, and they run in a sandbox without
access to the file system or network.

Each step name is an object:

| Field | Type | Meaning |
|---|---|---|
| `sent` | bool | the request was sent and answered |
| `status` | int | HTTP status (0 when not sent) |
| `ok` | bool | status is 2xx |
| `body` | string | response body (up to `safety.maxResponseBytes`) |
| `json` | any | parsed JSON body, `nil` if not JSON |
| `profile` | string | profile name |
| `identifiers` | []string | the profile's identifiers and owned `userId` values |
| `headers` | map | response headers, lower-case names |

Other names:

| Name | Meaning |
|---|---|
| `endpoint.method`, `endpoint.path` | operation under test (`/orders/{orderId}`) |
| `endpoint.secured` | the spec declares `security` for it |
| `endpoint.admin` | it is an admin function |
| `endpoint.tags` | its OpenAPI tags |
| `cfg.similarityThreshold` | `compare.similarityThreshold` |
| `identifiers` | identifiers of every profile |
| `similarity(a, b)` | structural JSON similarity in [0, 1], with `ignoreFields` and dynamic fields removed; non-JSON bodies are compared by hash and length |
| `evidence(body, ids)` | `body` contains one of `ids`. In JSON, a value shorter than 6 characters (such as user ID `2`) only counts in a field whose name contains owner, user, email, account or customer; in other bodies only values of 6+ characters are searched |
| `matrixForbids("step")` | the config's `matrix` does not allow that step's profile |
| `matrixAllows("step")` | the config's `matrix` has an entry for the endpoint that allows that step's profile. Both are `false` when no matrix entry matches the endpoint |

## Example: tenant isolation

Users of different tenants should never see each other's invoices. With
profiles `acme_user` and `globex_user` sharing `role: user`:

```yaml
id: ACME-TENANT-001
name: Cross-tenant invoice access
severity: critical
owasp: "API1:2023"
cwe: CWE-639
remediation: Scope every invoice query by the caller's tenant ID.
applies:
  methods: [GET]
  paths: ["/invoices/**"]
steps:
  - name: owner
    as: owner
    use: owner
  - name: intruder
    as: other_user
    use: owner
match: owner.ok && intruder.ok && similarity(owner.body, intruder.body) >= 0.9
confidence:
  high: evidence(intruder.body, owner.identifiers)
```

## Testing a rule

1. `authdiff rules validate my-rule.yaml`.
2. `authdiff scan -c authdiff.yaml --rules ./rules --include "/invoices/**" --dry-run`
   prints every request the rule would send, without sending any (only a URL
   spec is downloaded).
3. Run it against an endpoint that is vulnerable **and** one that is
   protected correctly. A rule is only useful when it stays silent on the
   second.

The vuln-lab (`make lab`) is a convenient target for both.
