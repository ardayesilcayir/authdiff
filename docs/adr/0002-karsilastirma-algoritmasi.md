# ADR-0002: Response comparison algorithm

**Status:** Accepted
**Date:** 2026-11-20
**Deciders:** Arda Yeşilçayır (maintainer)

## Context

An authorization bug has no signature. `GET /orders/101` is a valid request;
it is a bug only when the caller does not own order 101 and still receives it.
authdiff must therefore decide, for two identities, whether the attacker
"got the owner's data", automatically and without a hand-written
expectation for every endpoint.

Forces:

- **False positives kill adoption** (PRD §17.1). Public resources, responses
  that differ only in timestamps or request IDs, and generic error pages that
  return `200` must not become findings. Target: false positive rate under 10%
  and recall of at least 90% on the vuln-lab (PRD §16).
- **Responses are mostly JSON**, but HTML error pages, PDFs and empty `204`
  bodies happen and must not crash the comparison.
- **Determinism:** the same input must give the same findings, so CI results
  are stable.
- **Hostile input:** a target may return deeply nested or huge bodies.

## Decision

Use a differential test with an owner reference, an anonymous baseline and a
structural similarity score (PRD §7.1):

1. **Owner request**: the owner calls the endpoint with its own IDs. A
   non-2xx or empty response invalidates the test case; it is skipped, not
   reported.
2. **Stability measurement**: the owner request is sent a second time. Leaf
   paths whose values differ between the two responses are marked dynamic and
   excluded from comparison, together with the configured
   `compare.ignoreFields`.
3. **Attacker request**: another profile with the same role sends the same
   request with the owner's IDs.
4. **Anonymous baseline**: the request is sent without credentials. If the
   anonymous response is also similar to the owner's, the resource is public
   and no BOLA finding is raised.
5. **Decision**: a finding when the attacker gets a 2xx and
   `similarity(owner, attacker) >= compare.similarityThreshold` (0.85).
6. **Confidence**: `high` when the attacker's response contains the owner's
   identifiers (configured `identifiers` and owned `userId`s), otherwise
   `medium`.

**Similarity score.** Both JSON bodies are flattened into leaf paths with
canonical values (`$.items[0].price` → `12.5`), with a depth limit of 64.
After removing masked paths from both sides:

```
similarity = |paths present in both with equal values| / |union of paths|
```

An empty union scores 1.0 (which is why rules also require a non-empty owner
body). When neither body is JSON, identical bytes score 1.0 and anything else
`0.8 × min(len)/max(len)`, which can never reach the default threshold. JSON
against non-JSON scores 0.

The steps and the decision are expressed as YAML rule templates evaluated
with `expr` (`rules/bola-read.yaml`), so the same mechanism serves BOLA,
BFLA, missing authentication and custom rules.

## Options considered

### Option A: Status codes only

Owner 200 and attacker 200 → finding.

**Pros:** trivial, fast, no body parsing.
**Cons:** many APIs return `200` with an error body or an empty list for
unauthorized callers; public resources are flagged. High false positive rate.

### Option B: Exact body equality (hash)

**Pros:** simple, deterministic, no false positives from error pages.
**Cons:** any timestamp, request ID or per-user field (`viewerCanEdit`) breaks
equality; recall drops sharply on real APIs.

### Option C: Text diff (line or character based)

**Pros:** works on any content type.
**Cons:** sensitive to key order and formatting; the score has no notion of
fields, so it cannot ignore `$..updatedAt` precisely.

### Option D: Structural, Jaccard-like comparison with masking (chosen)

**Pros:** independent of key order and formatting; dynamic fields are learnt
from the target itself; configured ignore paths are precise; the score is
explainable in a report ("0.92 of fields identical"); deterministic.
**Cons:** one extra owner request per test; weak for non-JSON bodies (by
design, they rarely pass the threshold); a threshold to tune.

### Option E: Learned / ML classifier

**Pros:** could capture subtle cases.
**Cons:** needs training data, not explainable, not deterministic enough for
CI gating. Out of scope.

## Trade-off analysis

Option D sends twice the requests of a naive owner-versus-attacker test (repeat plus
anonymous baseline) to remove the main false positive classes: dynamic fields
(stability measurement), public data (anonymous baseline) and error bodies
with `200` (structure and value comparison, non-JSON penalty). It keeps
results deterministic and every number in a finding explainable. The
threshold of 0.85 tolerates a few per-viewer fields while staying far above
the score of a generic error object.

## Consequences

- Easier: adding new differential checks as YAML templates; explaining a
  finding with its similarity score and masked evidence.
- Easier: suppressing a known false positive by its stable finding ID.
- Harder: endpoints that return per-viewer variations of the same object may
  need `ignoreFields` entries.
- Harder: non-JSON resources (PDFs, images) are only detected when bodies are
  byte-identical, which is the case for the vuln-lab invoice PDF but not
  guaranteed elsewhere.
- Measured: on the vuln-lab, with destructive checks, all 8 expected
  (rule, method, path) tuples are found and no negative endpoint is
  reported (recall 1.00, false positive rate 0.00), verified by the e2e test.
- Revisit: the threshold default and the non-JSON score after testing on a
  second target (crAPI or VAmPI, PRD §16).

## Action items

1. [x] `compare.Flatten`, `Similarity`, `Evidence` with table tests and
   hostile-input tests (depth 10,000, 5 MB limit).
2. [x] BOLA read/write, BFLA and NOAUTH as templates using the algorithm.
3. [x] e2e test against the vuln-lab oracle in CI.
4. [ ] Benchmark on a second vulnerable API and document it in
   `docs/benchmarks.md`.
