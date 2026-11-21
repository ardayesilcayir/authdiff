# AD-METHOD-001: HTTP method swap bypass

| | |
|---|---|
| Severity | medium (CVSS 6.5 estimate) |
| OWASP | API5:2023 Broken Function Level Authorization |
| CWE | CWE-650 Trusting HTTP Permission Methods on the Server Side |
| Applies to | each path once; tries the methods the spec does **not** declare for it |
| Destructive | `PUT`, `PATCH` and `DELETE` probes run only with `--allow-destructive` |
| Rule | [`rules/method-swap.yaml`](../../rules/method-swap.yaml) (`kind: methodswap`, built-in logic) |

## What it finds

The documented methods of a path are protected, but an undocumented one is
served without the same checks. Example: `GET /orders/{id}` checks ownership,
but `DELETE /orders/{id}` also exists, is missing from the spec and has no
check.

## How it works

For each path, every candidate method (`POST`, `PUT`, `PATCH`, `DELETE`) that
the spec does not declare is sent with an empty JSON body (`{}`):

- as another non-admin user with the owner's IDs (or, when there is no such
  owner / other-user pair, as the first non-admin user, preferably one that
  owns the path IDs), and
- as the anonymous profile.

Safety limits:

- An `admin` profile is never used as the attacker: admins are expected to
  be allowed, and a destructive probe as admin would really change data.
- `PUT`, `PATCH` and `DELETE` are never swapped onto a path without path
  parameters (a collection such as `/orders`), where they could replace or
  wipe every object.
- A destructive probe is not sent when a path ID does not belong to a
  configured profile (it would be a guessed example or `1`); it is recorded
  as skipped.

A 2xx response to an undeclared method is a finding. `405 Method Not
Allowed`, `404`, `401` and `403` are the expected answers.

## How to fix

- Register only the methods you implement and let the framework answer `405`
  for the rest.
- Attach authorization to the resource rather than to individual method
  handlers, so every method shares it.
- Keep the OpenAPI spec complete: an undocumented route is also an untested
  route.
