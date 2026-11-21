# AD-NOAUTH-001: Missing authentication

| | |
|---|---|
| Severity | high (CVSS 8.1 estimate) |
| OWASP | API2:2023 Broken Authentication |
| CWE | CWE-306 Missing Authentication for Critical Function |
| Applies to | every operation |
| Template | [`rules/noauth.yaml`](../../rules/noauth.yaml) |

## What it finds

An endpoint that should require authentication answers an anonymous request.
Example: `GET /users/{userId}/profile` lost its auth dependency and returns
any user's profile to anyone.

## How it works

1. **Reference request**: a logged-in profile (`any_user`, preferably one that
   owns the path IDs) calls the endpoint. For destructive methods (`DELETE`,
   `PUT`, `PATCH`) this step is skipped (`skipDestructive: true`): a logged-in
   `DELETE` would delete the object (or, as an admin, the admin's own
   account) and the anonymous probe would then always get `404`.
2. **Anonymous request**: the same request without credentials.
3. **Decision**: the anonymous request gets a 2xx **and** at least one of the
   following holds:
   - the operation declares `security` in the OpenAPI spec (a requirement
     list that contains an empty object, such as `[{bearer: []}, {}]`, means
     authentication is optional and does not count),
   - the `matrix` does not allow anonymous access to it,
   - the anonymous response contains a profile's identifiers (user ID,
     e-mail).

   A destructive anonymous probe is sent only when the path IDs belong to a
   configured profile (see [configuration](../configuration.md#safety)).

   Endpoints that are public by design (no `security`, no matrix entry, no
   personal data in the response) are therefore not reported.
4. **Confidence**: `high` when identifiers appear in the anonymous response,
   otherwise `medium`.

## Example

```
GET /users/2/profile   (alice)       -> 200 {"id":2,"email":"alice@vuln.lab"}
GET /users/2/profile   (anonymous)   -> 200 {"id":2,"email":"alice@vuln.lab"}
```

## How to fix

- Make authentication the default for the whole API and opt out explicitly
  for public routes (global middleware or dependency), instead of opting in
  per route.
- Keep the OpenAPI `security` declarations in sync with the code; authdiff
  uses them to tell intentionally public endpoints from forgotten ones.
