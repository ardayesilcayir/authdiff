# AD-MASS-001: Mass assignment

| | |
|---|---|
| Severity | high (CVSS 8.1 estimate) |
| OWASP | API3:2023 Broken Object Property Level Authorization |
| CWE | CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Applies to | `POST`, `PUT`, `PATCH` operations with a JSON request body and a `GET` on the same path |
| Destructive | yes for `PUT`/`PATCH`: runs only with `--allow-destructive` |
| Rule | [`rules/mass-assignment.yaml`](../../rules/mass-assignment.yaml) (`kind: massassign`, built-in logic) |

## What it finds

The API copies client-supplied fields that should be server-controlled into
its model. Example: `PUT /users/me` with `{"role":"admin"}` makes the caller
an administrator.

## How it works

For every non-anonymous profile, writing its own object:

1. **Before**: `GET` on the same path records the current values.
2. **Injected write**: the normal request body plus the server-controlled
   fields that the request schema does **not** declare: `role` (`"admin"`),
   `isAdmin` / `is_admin` (`true`) and `ownerId` (another profile's user ID).
3. **After**: `GET` again.
4. **Decision**: an injected field now has the injected value and did not
   have it before. The persisted fields are named in the finding.

## Example

```
GET /users/me   (bob)                                 -> 200 {"id":3,"role":"user"}
PUT /users/me   (bob)  {"name":"bob","role":"admin"}  -> 200
GET /users/me   (bob)                                 -> 200 {"id":3,"role":"admin"}
```

## How to fix

- Bind request bodies to explicit input models that list only the fields a
  client may set (allow-list), never directly to the database model.
- Set server-controlled properties (`role`, `ownerId`, `isAdmin`, prices,
  balances) only in server code.
- Reject unknown fields (`additionalProperties: false`, strict decoders).
