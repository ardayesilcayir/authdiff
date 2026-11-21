---
title: "authdiff: Finding authorization bugs by diffing identities"
date: 2026-11-21
lang: en
tags: [security, api, bola, owasp, go, open-source]
description: "How I designed an open source CLI that finds BOLA/BFLA bugs, which signature scanners cannot see, by sending the same request as different identities and comparing the responses."
---

# authdiff: Finding authorization bugs by diffing identities

`GET /orders/42` is a valid request. The syntax is right, the headers are
right, the response is `200 OK`. A SQL injection scanner has nothing to catch
here, because there is no "bad input". If the caller does not own order 42 and
still receives it, the problem is not in the input but in **who is asking**.

That is exactly item one of the OWASP API Security Top 10 (2023): API1 Broken
Object Level Authorization (BOLA, formerly IDOR). Item five is its relative:
API5 Broken Function Level Authorization (BFLA), a regular user being able to
call `GET /admin/users`. What these bugs share is that they have no signature.
Payload lists, regexes and grepping responses for error messages cannot find
them. The only way to find them is to send the same request as different
identities and compare the results.

In this post I describe how I designed
[authdiff](https://github.com/ardayesilcayir/authdiff), an open source CLI that
does this automatically: the comparison algorithm, how I made the tool itself
safe, and a few embarrassing bugs that review caught during development.

## The core idea: identity diffing

authdiff reads an OpenAPI 3.0/3.1 spec, builds an endpoint inventory and sends
each request repeatedly as the profiles in the configuration. A profile is an
identity plus the objects it owns:

```yaml
profiles:
  alice:
    role: user
    auth: { type: bearer, token: "${env:ALICE_TOKEN}" }
    owns: { userId: [2], orderId: [101, 102], invoiceId: [9001] }
    identifiers: [alice@vuln.lab]
  bob:
    role: user
    auth: { type: bearer, token: "${env:BOB_TOKEN}" }
    owns: { userId: [3], orderId: [201, 202], invoiceId: [9002] }
  anonymous:
    role: none
    auth: { type: none }
```

Three roles tell you a lot:

- **Owner:** alice asks for her own order. This is the reference response.
- **Stranger:** bob, with the same role, sends the same request with alice's ID.
- **Anonymous:** the request is sent with no credentials at all.

If bob gets alice's response, there is BOLA. If the anonymous caller gets the
same response too, the resource is public and it is not BOLA.

You do not have to write the `owns` lists by hand; `harvest` collects IDs from
each profile's own responses (`GET /me/orders` → `$.items[*].id`).

You can also state the expectation explicitly. This is what the PRD calls the
authorization matrix:

```yaml
matrix:
  "GET /admin/**":         { allow: [admin] }
  "GET /orders/{orderId}": { allow: [admin, owner] }
  "POST /orders":          { allow: [admin, user] }
```

Every 2xx response the matrix does not allow is an `AD-MATRIX-001` finding.
The matrix is optional; without it, authdiff infers problems by comparing
owners with strangers. The signature feature of the HTML report is an
endpoint × profile heat map that shows how this matrix actually behaves.

## How the comparison works

The hard part is answering "did bob get alice's data?" for every endpoint
without a hand-written expectation. Status codes alone do not work: many APIs
return `200` with an empty list or an error body to unauthorized callers.
Hashing the bodies does not work either: a single `requestId` or timestamp
breaks equality. The approach I chose
([ADR-0002](https://github.com/ardayesilcayir/authdiff/blob/main/docs/adr/0002-karsilastirma-algoritmasi.md))
has six steps:

1. **Owner request.** alice sends `GET /orders/101`. If it is not 2xx or the
   body is empty, the test case is invalid and skipped, not reported.
2. **Stability measurement.** The same request is sent again as alice. Leaf
   paths whose values differ between the two responses are marked dynamic and
   excluded from comparison, together with the configured
   `compare.ignoreFields`.
3. **Attacker request.** bob sends the same request with alice's ID.
4. **Anonymous baseline.** The request is sent without credentials. If the
   anonymous response is also similar to the owner's, the resource is public
   and no BOLA finding is raised.
5. **Decision.** A finding when bob gets a 2xx and the masked similarity is at
   or above the threshold (default `0.85`).
6. **Confidence.** `high` when bob's response contains alice's identifiers
   (email, owned `userId`s), otherwise `medium`.

### The similarity score

Both JSON bodies are flattened into leaf paths, keeping each leaf's canonical
JSON value (`$.items[0].price` → `12.5`). Masked paths are removed from both
sides, then:

```
similarity = |paths present in both with equal values| / |union of paths|
```

It is a Jaccard-like score: independent of key order and formatting,
deterministic, and explainable in a report ("0.88 of fields identical"). The
core is a few lines:

```go
for p, va := range fa {
    if o.masked(p) {
        continue
    }
    union++
    if vb, ok := fb[p]; ok && vb == va {
        equal++
    }
}
for p := range fb {
    if !o.masked(p) {
        if _, ok := fa[p]; !ok {
            union++
        }
    }
}
```

For non-JSON bodies, identical bytes score `1.0` and anything else
`0.8 × min(len)/max(len)`, so it can never reach the default threshold. JSON
against non-JSON scores `0`.

### A small worked example

alice's two responses (steps 1 and 2):

```json
{"id": 101, "owner": {"id": 2, "email": "alice@vuln.lab"},
 "items": [{"sku": "KB-01", "qty": 1}], "total": 49.9, "status": "paid",
 "viewerCanEdit": true, "requestId": "a1f3", "updatedAt": "2026-11-21T10:00:00Z"}
```

In the second response only `requestId` differs (`"9c2e"`), so `$.requestId`
is dynamic; `$..updatedAt` is already in `ignoreFields`. What bob receives:

```json
{"id": 101, "owner": {"id": 2, "email": "alice@vuln.lab"},
 "items": [{"sku": "KB-01", "qty": 1}], "total": 49.9, "status": "paid",
 "viewerCanEdit": false, "requestId": "77b0", "updatedAt": "2026-11-21T10:00:05Z"}
```

After masking, the remaining paths are `$.id`, `$.owner.id`, `$.owner.email`,
`$.items[0].sku`, `$.items[0].qty`, `$.total`, `$.status`, `$.viewerCanEdit`.
The union is 8 and 7 have equal values (`viewerCanEdit` differs). Score
`7/8 = 0.875 ≥ 0.85`: a finding. The anonymous request got `401`, so the
resource is not public. bob's response contains `alice@vuln.lab`, so
confidence is `high`.

For contrast: had bob received `200` with `{"detail": "Not found"}`, no equal
path would be shared and the score would be `0`. The `0.85` threshold
tolerates a few per-viewer fields (like `viewerCanEdit`) while staying far
above the score of a generic error object.

Evidence matching has its own trap: a short ID like `2` appears everywhere.
So IDs shorter than 6 characters count as evidence only when the leaf's last
key contains `owner`, `user`, `email`, `account` or `customer`.

## Rules: YAML plus expr

Instead of hard-coding these steps, I wrote them as YAML templates whose
conditions are evaluated with [expr](https://github.com/expr-lang/expr). The
same mechanism serves BOLA, BFLA, NOAUTH and custom rules. This is the whole
of `rules/bola-read.yaml`:

```yaml
id: AD-BOLA-001
name: Broken object level authorization (read)
owasp: "API1:2023"
cwe: CWE-639
severity: high
description: >
  A user can read an object owned by another user by supplying its identifier.
  The response served to the non-owner matches the owner's response.
remediation: docs/rules/AD-BOLA-001.md
applies:
  methods: [GET]
  pathHasParam: true
  adminFunction: false
steps:
  - name: owner
    as: owner
    use: owner
    repeat: 2
  - name: attacker
    as: other_user
    use: owner
  - name: anon
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

`as` says who sends the request, `use` says whose IDs go into it.
`repeat: 2` is the stability measurement. The `len(owner.body) > 0` guard is
there because an empty union scores `1.0`. v1.0.0 ships eight built-in rules:
`AD-BOLA-001`, `AD-BOLA-002`, `AD-BFLA-001`, `AD-NOAUTH-001`, `AD-MASS-001`,
`AD-METHOD-001`, `AD-MATRIX-001`, `AD-LEAK-001`.

## Building a tool that is itself safe

A tool that sends requests with other people's credentials cannot be allowed
to hit the wrong host, use the wrong method or follow a leaking redirect. So
every safety control lives in the transport layer, not in the engines, as a
`RoundTripper` chain: scope → safe mode → rate limit → base. A newly written
rule cannot bypass them.

- **Scope allow-list.** `scope.allowHosts` is mandatory. Matching is exact on
  the normalized `host:port`; an entry that cannot be parsed can only shrink
  the scope. Redirects and the spec download go through the same check. A
  scan also refuses to start without `scope.acknowledgeAuthorization: true`.
- **Safe mode.** `DELETE`, `PUT` and `PATCH` are blocked by default and need
  `--allow-destructive`. Headers like `X-HTTP-Method-Override` and the
  `_method` query parameter are checked too, so a `POST` cannot smuggle a
  destructive method past the filter.
- **Rate limit.** 5 requests per second by default, keyed by normalized
  target.
- **Redaction.** Tokens, cookies, basic-auth credentials and JWT-shaped
  strings are masked in every output; report files are written `0600` and
  never through a symlink.
- **HTML report.** A single file, escaped by `html/template`, shipped with this
  CSP: `default-src 'none'; style-src 'unsafe-inline'; img-src data:`. The
  report contains content the target returned; that content must never get a
  chance to run a script.

Designing these was the easy part. The real lessons came from bugs review
caught.

### War story 1: one slow endpoint killed the whole scan

The engine detected cancellation with `errors.Is(err, context.DeadlineExceeded)`.
But `http.Client` timeouts also return `true` for that check. Result: when a
single slow endpoint hit its request timeout, the engine took it for "the user
cancelled the scan" and stopped everything. The fix (`aec9be7`): per-request
timeouts are recorded as failed probes, and only cancellation of the caller's
own context stops the run, which then returns the partial result. Later
(`7ae0ba9`) I ran each attempt under its own `context.WithTimeout` instead of
`http.Client.Timeout` and moved the rate limiter wait out of the timeout; that
wait was the source of spurious timeouts at low `--rate` values.

### War story 2: `..` IDs path-traversed to other endpoints

Some IDs are harvested from the target's own responses, so the target controls
them. `url.PathEscape("..")` still returns `..`; dots are valid path
characters. Put `..` into the `/orders/{orderId}` template and you get
`/orders/..`, which the server normalizes to a completely different resource;
with `--allow-destructive` that can be a `DELETE`. The fix (`2637509`) is
small:

```go
func escapeSegment(v string) string {
    switch v {
    case ".":
        return "%2E"
    case "..":
        return "%2E%2E"
    }
    return url.PathEscape(v)
}
```

### War story 3: the NOAUTH rule deleted the admin

`AD-NOAUTH-001` first sends an authenticated reference request, then an
anonymous one. Under `--allow-destructive`, for `DELETE /admin/users/{userId}`
the reference step ran as the admin profile with the admin's own `userId`: the
admin deleted itself, and the anonymous probe that followed always got `404`.
The fix (`259a372`): the reference step uses `skipDestructive: true` and never
sends destructive methods. The same commit stopped planning destructive
requests whose path IDs are not all owned by a configured profile, and made the
`DELETE` phase run sequentially (concurrency 1).

### War story 4: an https → http redirect leaked Authorization

Go's `http.Client` drops `Authorization` and cookies on a redirect only when
the redirect goes to a different domain; it keeps them on an `https` to `http`
downgrade to the same host, and it copies custom headers such as `X-API-Key`
on every redirect. So an in-scope but hostile response could move a token onto
a plaintext channel. The fix (`e492eae`): `CheckRedirect` refuses `https → http`
downgrades and redirects to a different `host:port`. The same commit makes the
base transport ignore `HTTP_PROXY`/`HTTPS_PROXY`; a proxy is used only when set
explicitly with `--proxy`, and it is logged. Network errors are now retried
only for `GET`/`HEAD`/`OPTIONS`.

## Testing strategy: a deliberately vulnerable lab as an oracle

I did not want to ship a security scanner because it "seems to work". The repo
contains a deliberately vulnerable FastAPI e-commerce API under `vuln-lab/`.
The front-matter of its `VULNERABILITIES.md` is a machine-readable oracle:

```yaml
expected:
  - id: V1
    rule: AD-BOLA-001
    method: GET
    path: /orders/{orderId}
    destructive: false
  # ... V2-V8
negatives:
  - method: GET
    path: /orders/{orderId}/status
  - method: GET
    path: /products/{id}
  # ...
```

There are eight expected findings (BOLA read and write, a PDF invoice, two
BFLA, NOAUTH, mass assignment, a `passwordHash` leak) and correctly protected
negative controls such as public products, `/me` and `/admin/stats`. Negatives
matter as much as positives; false positives kill adoption of this kind of
tool.

The test under `test/e2e` scans the lab, compares every `(rule, method, path)`
tuple with the oracle, and a single finding on a negative endpoint fails the
test. With destructive checks enabled the result is **recall 1.00 (8/8) and a
false positive rate of 0.00**. The E2E workflow also asserts that the SARIF
output contains findings (an empty SARIF means a broken scan) and uploads it
to GitHub code scanning, where findings appear under **Security → Code
scanning**.

Scoring 100% on a lab I wrote myself is an optimistic measurement, of course.
So the benchmark against a second target lives in its own document:
[docs/benchmarks.md](https://github.com/ardayesilcayir/authdiff/blob/main/docs/benchmarks.md).

## Ethics and the law

authdiff is designed to be used only on systems you own or have written
permission to test. Unauthorized access to computer systems is a crime in most
jurisdictions (for example the Computer Fraud and Abuse Act in the US, the
Computer Misuse Act in the UK, and articles 243–244 of the Turkish Penal Code).
That is why the defaults start "closed": `acknowledgeAuthorization` is
required, the scope list is required, destructive methods are off, and the
User-Agent identifies the tool (`authdiff (+https://github.com/ardayesilcayir/authdiff)`).
Even in a bug bounty program, read the scope and the rules: without permission,
the test "I can read another user's order" is itself access to someone else's
data.

## Try it

Install:

```sh
go install github.com/ardayesilcayir/authdiff/cmd/authdiff@v1.0.0
```

or grab a Linux, macOS or Windows (amd64/arm64) binary, with `checksums.txt`,
from the [v1.0.0 release](https://github.com/ardayesilcayir/authdiff/releases/tag/v1.0.0).
Docker image: `ghcr.io/ardayesilcayir/authdiff`.

The five-minute lab flow:

```sh
git clone https://github.com/ardayesilcayir/authdiff && cd authdiff
go install ./cmd/authdiff
make lab                                         # start the vuln-lab with Docker
set -a; source examples/vuln-lab.env; set +a     # the lab's FAKE tokens
authdiff scan -c examples/authdiff.yaml
```

The scan prints the findings and writes `results.json`, `results.sarif` and
`report.html` to `authdiff-out/`. The exit code is `1` because findings reached
`failOn: high`. To see the destructive bugs (V2, V5, V7), add
`--allow-destructive` and restart the lab afterwards; the scan mutates it.

For your own API, `authdiff init` writes a starter configuration and
`authdiff scan --dry-run` prints the request plan without sending requests to the endpoints. In
CI, `uses: ardayesilcayir/authdiff/action@v1` uploads the SARIF to code
scanning and fails the job at the `fail-on` threshold.

## Limits and roadmap

- Similarity is designed around JSON. Non-JSON resources such as PDFs are only
  caught when the bytes are identical; that holds for the lab's invoice PDF but
  is not guaranteed elsewhere.
- Endpoints with many per-viewer fields may need `ignoreFields`, and the
  threshold default will be revisited based on the second-target measurement.
- The tool depends on an OpenAPI spec; an incomplete spec means an incomplete
  inventory.
- There is no token refresh; in long scans you have to renew expiring tokens
  yourself.

After v1.0 (the P2 items in the PRD): Swagger 2.0 support (automatic
conversion to 3.0), HAR / Burp XML import for APIs without a spec, token
refresh through a login endpoint, and GraphQL support.

Code, rules and the lab: [github.com/ardayesilcayir/authdiff](https://github.com/ardayesilcayir/authdiff).
The contributions that would help most are new rule templates, false positive
reports and measurements on a second target.
