# AD-MATRIX-001: Authorization matrix violation

| | |
|---|---|
| Severity | high (CVSS 8.1 estimate) |
| OWASP | API5:2023 Broken Function Level Authorization |
| CWE | CWE-285 Improper Authorization |
| Applies to | endpoints matched by a `matrix` entry in the config; inactive without a matrix |
| Rule | [`rules/matrix.yaml`](../../rules/matrix.yaml) (`kind: matrix`, built-in logic) |

## What it finds

Observed access contradicts the policy you declared. You write down which
roles may call which endpoints, and authdiff reports every profile that got a
2xx where the matrix does not allow it.

```yaml
matrix:
  "GET /admin/**":         { allow: [admin] }
  "GET /orders/{orderId}": { allow: [admin, owner] }
  "POST /orders":          { allow: [admin, user] }
```

## How it works

No extra requests are sent. After all other checks have run, every response
observed during the scan is compared with the matrix:

- A profile is allowed when its **name** or its **role** is listed, or when
  `owner` is listed and the request used the profile's own IDs.
- Anonymous access must be listed explicitly (`anonymous`, or the anonymous
  profile's role).
- Keys are globs: `*` matches one path segment and `**` any number of
  segments; an optional method prefix restricts the method.
- A method + path + attacker that already has a finding from another rule is
  not reported again.

The matrix also feeds other rules: an entry that allows only `admin` marks
the endpoint as an admin function (AD-BFLA-001), and an entry that does not
allow anonymous access makes AD-NOAUTH-001 report anonymous 2xx responses.

## How to fix

Either the code or the matrix is wrong. Fix the authorization check or, if
the access is intended, update the matrix so the policy stays the source of
truth.
