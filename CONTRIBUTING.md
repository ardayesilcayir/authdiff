# Contributing to authdiff

Thanks for helping. Bug reports, new rules, false positive reports with a
reproducer, and documentation fixes are all welcome.

## Before you start

- For a bug, open an issue with the bug report template. Remove tokens and
  real data from configs and evidence.
- For a larger change (a new check kind, a new output format, a config
  change), open a feature request first so we can agree on the design.
- Security problems in authdiff itself go through [SECURITY.md](SECURITY.md),
  not issues.
- Only test against systems you are authorized to test. Use the vuln-lab for
  development.

## Setup

You need Go 1.23+, Docker (for the vuln-lab) and, for lab tests, Python 3.12.

```sh
git clone https://github.com/ardayesilcayir/authdiff && cd authdiff
go build ./...
go test ./...
```

| Task | Command |
|---|---|
| Unit, engine and golden tests | `go test ./...` (CI adds `-race`) |
| Coverage of `internal/` (must stay ≥ 80%) | `make cover` |
| Lint (must be clean) | `make lint` |
| Start / recreate / stop the lab | `make lab` / `make lab-restart` / `make lab-stop` |
| End-to-end test (recreates the lab first) | `make e2e` |
| Lab tests | `cd vuln-lab && python -m pytest` |
| Update golden files after an intended output change | `go test ./internal/report -update` |

The vuln-lab is stateful: destructive scans delete users and change roles.
Always recreate it before an e2e run (`make e2e` does this for you).

## Code guidelines

- Code, comments and docs are in English. `README.md` is Turkish and
  `README.en.md` is the English version; update both together when you change
  the README.
- Package boundaries are deliberate: only `internal/cli` imports cobra,
  `internal/report` imports only `internal/finding`, and **only
  `internal/transport` touches the network**. New checks must send requests
  through the engine's client so scope, safe mode, rate limit and masking
  apply.
- Never log or print a secret unmasked. Add a masking test when you add a new
  place where request or response data is written.
- Output must be deterministic: sort before printing, no map iteration order
  in reports.
- Every rule needs a "finds it" test **and** a "stays silent" test against a
  correctly protected endpoint.
- Run `gofmt` on the files you change.

## Adding a rule

1. Prefer a YAML template ([docs/writing-rules.md](docs/writing-rules.md)).
   Built-in templates live in `rules/` and are embedded into the binary.
2. Add engine tests with `httptest` servers: one vulnerable, one protected.
3. Write `docs/rules/<ID>.md`: what it finds, how it works, an example, how to
   fix it. Reference it from the rule's `remediation`.
4. If the vuln-lab should demonstrate it, add the endpoint and update the
   front-matter in `vuln-lab/VULNERABILITIES.md`; the e2e test uses it as the
   oracle.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(engine): ...`, `fix(transport): ...`, `docs: ...`, `test: ...`,
  `ci: ...`.
- Keep pull requests focused; describe the behaviour change and how you
  tested it.
- CI must be green: tests with the race detector, coverage gate, lint,
  govulncheck, CodeQL, lab tests and the e2e scan.
- Add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for
  user-visible changes.

By contributing you agree that your contribution is licensed under the
[MIT License](LICENSE).

## Releasing (maintainers)

1. Move the `[Unreleased]` entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading and commit.
2. Tag and push the full version; this triggers the release workflow
   (GoReleaser binaries, checksums, GHCR image):
   `git tag -a vX.Y.Z -m "authdiff vX.Y.Z" && git push origin vX.Y.Z`
3. Move the major tag used by the GitHub Action to the same commit. Only
   full `vX.Y.Z` tags trigger a release, so this does not publish anything:
   `git tag -fa v1 vX.Y.Z^{} -m "authdiff Action v1 -> vX.Y.Z" && git push -f origin v1`
