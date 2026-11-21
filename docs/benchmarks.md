# Benchmarks

authdiff is developed against its own [vuln-lab](../vuln-lab), so a scan of
the lab mostly shows that the tool finds what it was built to find. This page
records scans of a second, independent target that authdiff was not written
for, as required by the PRD success metric "second-target validation: at
least 3 real findings on OWASP crAPI or VAmPI".

| Target | Date | authdiff | True positives | False positives | In-scope recall |
|---|---|---|---|---|---|
| [VAmPI](#vampi) (`erev0s/vampi:latest`, vulnerable mode) | 2026-11-21 | `1.0.0` (commit `3892dd6` + the fix below) | 7 findings / 3 distinct VAmPI vulnerabilities | 2 findings / 1 endpoint | 3 of 4 classes |

## VAmPI

[VAmPI](https://github.com/erev0s/VAmPI) is a deliberately vulnerable Flask
REST API (MIT license) with an OpenAPI 3 spec and a published list of
vulnerabilities. It identifies users and books by name
(`/users/v1/{username}`, `/books/v1/{book_title}`) and issues HS256 JWTs from
`POST /users/v1/login`. `GET /createdb` resets the database and seeds three
users: `name1`, `name2` and the admin `admin`, each with one book whose title
is random.

### Setup

VAmPI is vulnerable on purpose: bind it to `127.0.0.1` only.

```sh
docker run -d --name vampi -p 127.0.0.1:5000:5000 erev0s/vampi:latest
curl -s http://localhost:5000/          # ... "vulnerable":1

go build -ldflags "-X main.version=1.0.0 -X main.commit=$(git rev-parse --short HEAD)" \
  -o authdiff ./cmd/authdiff
./authdiff version                      # authdiff 1.0.0 (commit 3892dd6, ...)
```

[`examples/vampi-setup.sh`](../examples/vampi-setup.sh) prepares the target.
Source it in the shell that runs the scan:

```sh
. examples/vampi-setup.sh
```

It calls `GET /createdb` (retrying: VAmPI's random seed titles sometimes
collide and the call returns `500`), logs in as `admin`, `name1` and `name2`
with VAmPI's public demo passwords, adds one book with a known title per
user (`admin-book`, `name1-book`, `name2-book`) and exports
`VAMPI_ADMIN_TOKEN`, `VAMPI_NAME1_TOKEN` and `VAMPI_NAME2_TOKEN`. Tokens only
exist in that shell's environment; none is written to disk or shown here.

### Configuration

[`examples/vampi.yaml`](../examples/vampi.yaml), summarised:

| Section | Value |
|---|---|
| `target.spec` | [`examples/vampi-openapi.yml`](../examples/vampi-openapi.yml): VAmPI's `openapi_specs/openapi3.yml`, copied unmodified with an MIT attribution header (13 operations) |
| `scope` | `allowHosts: [localhost:5000]`, `acknowledgeAuthorization: true` |
| `safety` | `rate: 10`, `concurrency: 2`, `allowDestructive: false` (the destructive run adds `--allow-destructive`) |
| `profiles` | `admin` (role `admin`), `name1` and `name2` (role `user`), `anonymous` (`auth: none`); bearer tokens from `${env:VAMPI_*_TOKEN}` |
| `owns` | `username: [<own name>]`, `book_title: [<name>-book]` per profile |
| `identifiers` | each user's e-mail and the secret of their book |
| `matrix` | VAmPI's README policy: user list and user lookup are public; `_debug` and `DELETE /users/v1/{username}` are admin only; password, e-mail and book secret are owner only |
| `filter.exclude` | `GET /createdb`: it drops and re-seeds the database, which would invalidate every `owns` entry mid-scan |

No `harvest` is configured: `GET /books/v1` lists every user's books, so
extracting titles from it would credit every book to every profile.

### Runs

Each run starts from a fresh database (`. examples/vampi-setup.sh`). Outputs
were written to a scratch directory, not to the repository.

| Run | Command | Requests | Blocked | Findings |
|---|---|---|---|---|
| Dry run | `authdiff scan -c examples/vampi.yaml --dry-run` | 0 sent, 100 planned (27 destructive) | n/a | n/a |
| Safe mode | `authdiff scan -c examples/vampi.yaml` | 100 | 27 | 5 |
| Destructive | `authdiff scan -c examples/vampi.yaml --allow-destructive` | 100 | 0 | 9 |
| Destructive, no `matrix` | same, with the `matrix` section removed | 98 | 0 | 5 |

Every run took 7 to 10 seconds and had 0 errors. Both scans exit `1`
(`failOn: high`).

### Findings (destructive run)

Every finding was checked by hand against VAmPI's source and, for writes,
against the database state afterwards (`GET /users/v1/_debug`).

| # | Rule | Method | Path | Attacker → victim | Safe mode | Verdict | VAmPI vulnerability |
|---|---|---|---|---|---|---|---|
| 1 | AD-BOLA-001 | GET | `/books/v1/{book_title}` | name2 → name1 | yes | TP | Broken Object Level Authorization: name2 reads `name1-book` with its secret; anonymous gets `401` |
| 2 | AD-BOLA-001 | GET | `/books/v1/{book_title}` | name1 → name2 | yes | TP | same, other direction |
| 3 | AD-NOAUTH-001 | GET | `/users/v1/_debug` | anonymous → admin | yes | TP | Excessive Data Exposure through debug endpoint: every user's plaintext password and admin flag, without a token |
| 4 | AD-BFLA-001 | GET | `/users/v1/_debug` | name1 → admin | yes | TP | same endpoint, as a normal user (admin function by the matrix) |
| 5 | AD-BFLA-001 | GET | `/users/v1/_debug` | name2 → admin | yes | TP | same |
| 6 | AD-MATRIX-001 | PUT | `/users/v1/{username}/password` | name2 → matrix | no | TP | Unauthorized Password Change: name2's `PUT /users/v1/name1/password` returns `204` and name1's password is changed |
| 7 | AD-MATRIX-001 | PUT | `/users/v1/{username}/password` | name1 → matrix | no | TP | same, other direction |
| 8 | AD-MATRIX-001 | PUT | `/users/v1/{username}/email` | name2 → matrix | no | FP | none: VAmPI ignores `{username}` and changes the **caller's** own e-mail; name1's e-mail is unchanged |
| 9 | AD-MATRIX-001 | PUT | `/users/v1/{username}/email` | name1 → matrix | no | FP | same |

All nine are `high` severity and `high` confidence. The safe-mode run reports
findings 1 to 5: the `PUT` requests behind 6 to 9 are blocked there.

**Why 8 and 9 are false positives.** AD-MATRIX-001 judges the response, not
its effect: a `204` to a request that names another user contradicts the
declared "owner only" policy. VAmPI's `update_email` looks the user up from
the token and never reads the path parameter, so nothing of name1's changes.
Telling the two apart needs a read-back of the victim's state after the
write, which authdiff does not do for matrix checks. Accept them with
`.authdiff-ignore`; finding IDs are stable:

```
25bdfb4155a5  # AD-MATRIX-001 PUT /users/v1/{username}/email name2: VAmPI writes the caller's own e-mail
f13ac0f5853a  # AD-MATRIX-001 PUT /users/v1/{username}/email name1: same
```

**Without a matrix** (inference only) authdiff reports findings 1 to 3 plus
`AD-NOAUTH-001` on `GET /users/v1` and `GET /users/v1/{username}`. Those two
return user names and e-mails to anonymous callers, which VAmPI's README
describes as intended ("an unregistered user can see minimal information
about the dummy users"), so they are false positives of that run. Declaring
them public in the matrix (`allow: [anonymous, user, admin]`) silences them;
before the fix below it did not.

**True negatives worth noting.** `DELETE /users/v1/{username}` by name1 and
name2 (`401 Only Admins may delete users!`), anonymous calls to every
token-protected operation (`401`), method swaps on every path, and the mass
assignment probe of `POST /books/v1` produced no finding.

### Recall and precision

VAmPI lists nine vulnerabilities. Four are authorization or data exposure
problems inside authdiff's scope (PRD §3 goal 3: BOLA, BFLA, mass assignment,
missing authentication).

| VAmPI vulnerability | In scope | Found | Rule |
|---|---|---|---|
| Broken Object Level Authorization | yes | yes (safe mode) | AD-BOLA-001 |
| Excessive Data Exposure through debug endpoint | yes | yes (safe mode) | AD-NOAUTH-001, AD-BFLA-001 |
| Unauthorized Password Change | yes | yes (destructive, with matrix) | AD-MATRIX-001 |
| Mass Assignment (`admin: true` on register) | yes | **no** | see misses |
| SQL injection (`GET /users/v1/{username}`) | no: input-based testing (PRD §3) | n/a | |
| RegexDoS (`PUT /users/v1/{username}/email`) | no: DoS (PRD §3) | n/a | |
| Lack of Resources & Rate Limiting | no: DoS / brute force (PRD §3) | n/a | |
| User and Password Enumeration (login messages) | no: credential brute force (PRD §3) | n/a | |
| JWT authentication bypass via weak signing key | no: token forging / key cracking | n/a | |

| Configuration | Recall (in-scope classes) | Precision (findings) | Precision (distinct rule, method, path) |
|---|---|---|---|
| Destructive, with matrix | 3/4 = 0.75 | 7/9 = 0.78 | 4/5 = 0.80 |
| Safe mode, with matrix | 2/4 = 0.50 | 5/5 = 1.00 | 3/3 = 1.00 |
| Destructive, no matrix | 2/4 = 0.50 | 3/5 = 0.60 | 2/4 = 0.50 |

### Misses

- **Mass assignment on `POST /users/v1/register`.** VAmPI accepts
  `"admin": true` from anyone registering (verified by hand: the new user is
  stored with `admin: true`). AD-MASS-001 does not test this operation, for
  two reasons. It reads the written object back with the `GET` of the same
  path, and `/users/v1/register` has none; the effect is only visible after
  logging in as the new user and calling `GET /me`, a multi-step flow v1
  does not automate (PRD §3: no automatic login flows). And its injected
  fields are `role`, `isAdmin`, `is_admin` and `ownerId`, not a bare `admin`.
- **Unauthorized Password Change without a matrix.** AD-BOLA-002 first has
  the owner read the object with `GET` on the same path, to prove the object
  exists and belongs to the owner. `/users/v1/{username}/password` is
  write-only (`GET` returns `405`), so the rule never fires; the attacker's
  `PUT` was sent and succeeded (name1's password changed), but nothing
  compares it. A matrix entry is the way to cover write-only endpoints.
  Without a read-back the rule could not tell this endpoint from the e-mail
  one above, where the same `204` is harmless.
- **AD-LEAK-001 on `GET /users/v1/_debug`.** The response carries plaintext
  `password` fields, but VAmPI's spec declares `password` in that response
  schema, and AD-LEAK-001 only reports sensitive keys the schema does not
  declare. The exposure is still reported, by AD-NOAUTH-001 and AD-BFLA-001.
- **Unauthenticated `GET /createdb`.** Anyone can wipe and re-seed the
  database. It is not in VAmPI's list and was excluded from the scan on
  purpose; scanning it would reset the target mid-scan.

### Engine change from this benchmark

The first run reported the two public user-directory endpoints as missing
authentication, and declaring them public in the matrix did not help:
AD-NOAUTH-001 fired whenever the anonymous response contained a profile
identifier, even when the matrix explicitly allowed anonymous access. That
contradicted the matrix documentation ("if the access is intended, update the
matrix"). The fix adds a `matrixAllows("step")` expression helper
([writing-rules.md](writing-rules.md#expressions)) and the NOAUTH template now
requires `!matrixAllows("anon")`. Without a matching matrix entry nothing
changes. Regression tests: `TestNOAUTHMatrixAllowsAnonymous`
(`internal/engine`) and `TestEvalNoAuthMatrixAllows` (`internal/rules`); the
vuln-lab e2e stays at recall 1.00 (8/8) and false positive rate 0.00.

### Reproduce

```sh
docker run -d --name vampi -p 127.0.0.1:5000:5000 erev0s/vampi:latest
go build -o authdiff ./cmd/authdiff

. examples/vampi-setup.sh
./authdiff scan -c examples/vampi.yaml --dry-run
./authdiff scan -c examples/vampi.yaml -o /tmp/vampi-safe

. examples/vampi-setup.sh          # destructive runs change passwords and e-mails
./authdiff scan -c examples/vampi.yaml --allow-destructive -o /tmp/vampi-destructive

docker rm -f vampi
```

Expected: 5 findings in safe mode and 9 in the destructive run, as in the
tables above. Finding IDs are stable across runs; book titles are fixed by
the setup script, so the results do not depend on VAmPI's random seed.
