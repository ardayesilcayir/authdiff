# ADR-0001: Go as the implementation language

**Status:** Accepted
**Date:** 2026-11-20
**Deciders:** Arda Yeşilçayır (maintainer)

## Context

authdiff is a security testing CLI that runs on developer laptops, in CI
runners and in pentest environments. The requirements that shape the language
choice (PRD §6, §8):

- **Distribution:** one static binary for Linux, macOS and Windows on amd64
  and arm64. Users should not need a language runtime, and a distroless Docker
  image should work.
- **Concurrent HTTP:** hundreds to thousands of requests per scan with a
  global rate limit, bounded concurrency, retries and per-request timeouts.
- **Safety in the transport:** scope checks, safe mode and secret masking must
  be one HTTP middleware chain that every check goes through.
- **Ecosystem fit:** the security tools this audience already uses (nuclei,
  ffuf, httpx, subfinder) are Go binaries installed with `go install`.
- **Constraints:** a single developer, about 10 weeks at 10 to 12 hours a
  week; the maintainer knows Go and Python.

## Decision

Write authdiff in Go (module `github.com/ardayesilcayir/authdiff`, `go 1.23`).
Keep the dependency set small: cobra (CLI), kin-openapi (spec parsing),
yaml.v3, x/time/rate, x/sync/errgroup, expr-lang/expr (rule expressions),
gjson, lipgloss. Comparison, SARIF and HTML reporting are implemented in the
project itself.

The deliberately vulnerable demo API (vuln-lab) is written in Python/FastAPI
instead, because FastAPI generates its OpenAPI document automatically and new
vulnerabilities take a few lines to add. It is a test fixture, not part of the
shipped tool.

## Options considered

### Option A: Go

| Dimension | Assessment |
|---|---|
| Complexity | Low: standard `net/http` with a custom `RoundTripper` chain covers scope, rate limit, safe mode and recording |
| Cost | Free toolchain; cross-compilation is built in (`GOOS`/`GOARCH`) |
| Distribution | Static binary, `CGO_ENABLED=0`, distroless image, GoReleaser |
| Familiarity | Good; matches the target audience's tooling |

**Pros:** single binary; goroutines and `errgroup` for bounded concurrency;
`html/template` escapes HTML by default (reports render untrusted responses);
`govulncheck`, CodeQL and golangci-lint support; `go install` as an
installation path for the GitHub Action.
**Cons:** more verbose than Python for JSON tree handling; no mature
structural-JSON-diff library that fits, so it is written in house (which ADR
0002 wants anyway).

### Option B: Python

| Dimension | Assessment |
|---|---|
| Complexity | Low to write; packaging is the hard part |
| Cost | Free |
| Distribution | Needs an interpreter and virtualenv, or PyInstaller bundles per platform |
| Familiarity | Good |

**Pros:** fastest prototyping; rich HTTP and OpenAPI libraries.
**Cons:** no single static binary; dependency conflicts in CI images; asyncio
rate limiting and cancellation are more error-prone; slower start-up for
CI use.

### Option C: Rust

| Dimension | Assessment |
|---|---|
| Complexity | High: async runtime choice, lifetimes in a middleware chain |
| Cost | Free |
| Distribution | Static binary, comparable to Go |
| Familiarity | Low |

**Pros:** performance and memory safety; good binaries.
**Cons:** learning curve does not fit the 10-week single-developer budget;
OpenAPI 3.1 support in the ecosystem is less mature than kin-openapi.

### Option D: TypeScript (Node.js)

**Pros:** good OpenAPI tooling, familiar to many API developers.
**Cons:** needs the Node runtime or a large bundled binary; weaker fit with
the security tooling ecosystem.

## Trade-off analysis

The deciding factors are distribution and the transport design. Network
throughput is limited by the rate limit (5 requests per second by default),
not by the language, so Rust's performance does not buy much. Python would be
quickest to write but hardest to ship as one file to every CI runner. Go
gives a single binary and a standard-library HTTP stack whose `RoundTripper`
interface makes "every request passes scope, safe mode and masking" a
structural property rather than a convention, at an acceptable cost in
verbosity.

## Consequences

- Easier: releases (GoReleaser builds 6 platform targets plus a Docker
  image), installation in the GitHub Action (`go install ...@version`), static
  analysis in CI.
- Easier: enforcing safety in one place; detection checks receive a client
  and cannot open their own connections.
- Harder: the structural JSON comparison, SARIF structures and HTML report are
  maintained in house.
- Harder: contributors who only know Python need Go to add built-in checks;
  YAML rule templates (docs/writing-rules.md) lower that barrier for most new
  tests.
- Revisit: if GraphQL or gRPC support (v2) needs libraries that only exist in
  another ecosystem.

## Action items

1. [x] Pin dependencies and the `go 1.23` directive in `go.mod`.
2. [x] Transport middleware chain: scope, safe mode, rate limit, recording.
3. [x] GoReleaser config for linux/darwin/windows × amd64/arm64 and the
   distroless image.
4. [ ] Signed releases and SBOM (Cosign, Syft): P2.
