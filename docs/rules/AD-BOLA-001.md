# AD-BOLA-001: Broken object level authorization (read)

| | |
|---|---|
| Severity | high (CVSS 8.1 estimate) |
| OWASP | API1:2023 Broken Object Level Authorization |
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| Applies to | `GET` operations with a path parameter that are not admin functions |
| Template | [`rules/bola-read.yaml`](../../rules/bola-read.yaml) |

## What it finds

A user reads an object that belongs to another user just by putting the
other user's ID in the URL (also called IDOR). Example: bob calls
`GET /orders/101` and receives alice's order.

## How it works

For every pair of profiles with the same `role` where one (the **owner**) owns
an ID for every path parameter (from `owns` or `harvest`):

1. **Owner request**, sent twice. Fields that differ between the two
   responses (timestamps, request IDs) are marked dynamic and ignored. If the
   owner does not get a non-empty 2xx, the pair is skipped: the object does not
   exist or the config is wrong.
2. **Attacker request**: the other profile sends the same request with the
   owner's IDs.
3. **Anonymous baseline**: the same request without credentials. If the
   anonymous response also matches the owner's, the resource is public and no
   BOLA finding is raised (AD-NOAUTH-001 decides whether that is a problem).
4. **Decision**: the attacker gets a 2xx and the structural similarity of its
   response to the owner's is at least `compare.similarityThreshold`
   (default 0.85).
5. **Confidence**: `high` if the attacker's response contains one of the
   owner's identifiers (its `identifiers`, such as the e-mail address, plus
   its owned `userId` values), otherwise `medium`.

## Example

```
GET /orders/101   Authorization: Bearer ****GqI (alice)  -> 200 {"id":101,"ownerId":2,...}
GET /orders/101   Authorization: Bearer ****jts (bob)    -> 200 {"id":101,"ownerId":2,...}
GET /orders/101   (anonymous)                            -> 401
```

Similarity 1.00 and `ownerId` 2 is alice's user ID: a finding with high
confidence.

## How to fix

- Check ownership on the server for every object access, after loading the
  object and before returning it: `order.ownerId == currentUser.id`, or a
  policy that allows the caller's role.
- Do it in one place (repository layer, policy middleware) so new endpoints
  cannot forget it.
- Return `404` rather than `403` for objects the caller may not see, so IDs
  cannot be enumerated.
- Random, non-sequential IDs (UUIDs) make guessing harder but are **not** an
  authorization control.

## False positives

Objects that are meant to be shared between users of the same role (team
documents, profiles visible to every logged-in user) look like BOLA. Add the
finding ID to `.authdiff-ignore` with a comment that explains why.
