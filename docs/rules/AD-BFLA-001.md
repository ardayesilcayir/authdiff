# AD-BFLA-001: Broken function level authorization (admin function)

| | |
|---|---|
| Severity | high (CVSS 8.1 estimate) |
| OWASP | API5:2023 Broken Function Level Authorization |
| CWE | CWE-285 Improper Authorization |
| Applies to | admin functions: a path segment or tag named `admin`, or a `matrix` entry that allows only `admin` |
| Destructive | `DELETE`/`PUT`/`PATCH` admin functions run only with `--allow-destructive` |
| Template | [`rules/bfla-admin.yaml`](../../rules/bfla-admin.yaml) |

## What it finds

A regular user calls a function meant for administrators. Example:
`GET /admin/users` checks that the caller is logged in, but not that the
caller is an admin.

## How it works

For every non-admin profile (`low_priv`):

1. **Admin reference**: the admin profile calls the endpoint. For destructive
   methods this step is skipped, so a delete is not sent twice.
2. **Attacker request**: the low-privileged profile calls the same endpoint.
3. **Decision**: the attacker gets a 2xx, and the admin request either was not
   sent or also succeeded (so the endpoint exists and works).
4. **Confidence**: `high` if the admin's and the attacker's responses are
   similar (at least the threshold), otherwise `medium`.

## Example

```
GET /admin/users   (admin)   -> 200 [{"id":1,...},{"id":2,...},{"id":3,...}]
GET /admin/users   (alice)   -> 200 [{"id":1,...},{"id":2,...},{"id":3,...}]
```

## How to fix

- Enforce the role on the server for every administrative route, ideally with
  a deny-by-default route group (`/admin/**` requires `role == admin`).
- Do not rely on the UI hiding admin buttons.
- Declare the expected policy in `matrix` so authdiff also checks admin
  functions that do not live under `/admin`.
