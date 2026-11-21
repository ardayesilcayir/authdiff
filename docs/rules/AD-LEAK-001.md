# AD-LEAK-001: Sensitive data exposure

| | |
|---|---|
| Severity | medium (CVSS 6.5 estimate) |
| OWASP | API3:2023 Broken Object Property Level Authorization (excessive data exposure) |
| CWE | CWE-213 Exposure of Sensitive Information Due to Incompatible Policies |
| Applies to | `GET` operations |
| Rule | [`rules/sensitive-leak.yaml`](../../rules/sensitive-leak.yaml) (`kind: leak`, built-in logic) |

## What it finds

A response contains fields that look like secrets and that the response
schema does not declare. Example: `GET /users/{userId}` returns the user's
`passwordHash`.

## How it works

1. Each `GET` endpoint is called once by a logged-in profile (`any_user`).
2. The JSON response is flattened into leaf paths (`$.items[0].passwordHash`).
3. A key is reported when its name matches
   `password|passwd|secret|token|apikey|api_key|ssn|hash` (case-insensitive)
   **and** the operation's response schema does not declare it.

Declared fields are treated as intentional (for example the `token` returned
by a login endpoint).

## Example

```
GET /users/2   (admin)   -> 200 {"id":2,"email":"alice@vuln.lab","passwordHash":"..."}
```

`passwordHash` is not part of the documented response schema.

## How to fix

- Serialize responses through explicit output models that list the public
  fields; never return database rows as they are.
- Never send password hashes, internal tokens or keys to clients, not even to
  the owner of the record.
