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

- as another user with the owner's IDs (or as any user when there is no
  owner / other-user pair), and
- as the anonymous profile.

A 2xx response to an undeclared method is a finding. `405 Method Not
Allowed`, `404`, `401` and `403` are the expected answers.

## How to fix

- Register only the methods you implement and let the framework answer `405`
  for the rest.
- Attach authorization to the resource rather than to individual method
  handlers, so every method shares it.
- Keep the OpenAPI spec complete: an undocumented route is also an untested
  route.
