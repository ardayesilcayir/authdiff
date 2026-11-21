# AD-BOLA-002: Broken object level authorization (write)

| | |
|---|---|
| Severity | high (CVSS 8.1 estimate) |
| OWASP | API1:2023 Broken Object Level Authorization |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| Applies to | `PUT`, `PATCH`, `DELETE` operations with a path parameter that are not admin functions |
| Destructive | yes: runs only with `--allow-destructive` or `safety.allowDestructive: true` |
| Template | [`rules/bola-write.yaml`](../../rules/bola-write.yaml) |

## What it finds

A user modifies or deletes an object owned by another user. Example: bob
sends `PATCH /orders/101` and changes alice's order.

## How it works

For every owner / other-user pair of the same role:

1. **Owner check**: the owner reads the object with `GET` on the same path. If
   that fails, the object does not exist for the owner and the pair is skipped.
2. **Attacker write**: the other user sends the state-changing request
   (`PUT`/`PATCH`/`DELETE`) with the owner's IDs and the example body from the
   spec (or from `bodies` in the config).
3. **Decision**: the attacker gets a 2xx.
4. **Confidence**: `high` if the attacker's response contains the owner's
   identifiers, otherwise `medium`.

Write checks run after the read checks (phases: `GET`/`POST`, then
`PUT`/`PATCH`, then `DELETE`), so reads see the original data.

## Example

```
GET   /orders/101   (alice)                         -> 200
PATCH /orders/101   (bob)  {"status":"cancelled"}   -> 200 {"id":101,"ownerId":2,"status":"cancelled"}
```

## How to fix

Apply the same ownership check as for reads on every write path: load the
object, verify that the caller may change it, then apply the change.
Handlers that bind a `PATCH` body directly to a database row are a common
source of this bug.

## Notes

This rule changes data. Run it only against test environments you can reset.
