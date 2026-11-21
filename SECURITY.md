# Security policy

authdiff handles credentials and talks to systems it does not own, so bugs in
the tool itself matter. Thank you for reporting them responsibly.

## Supported versions

| Version | Supported |
|---|---|
| latest 1.x release | yes |
| older releases, `main` snapshots | best effort |

## Reporting a vulnerability

**Do not open a public issue.** Report privately through
[GitHub private vulnerability reporting](https://github.com/ardayesilcayir/authdiff/security/advisories/new)
(Security → Report a vulnerability).

Please include:

- the authdiff version (`authdiff version`) and platform,
- what an attacker can do and under which conditions,
- steps or a minimal config / spec / server response that reproduces it
  (remove real tokens).

What to expect:

- acknowledgement within 7 days,
- an assessment and, for a confirmed issue, a fix plan within 30 days,
- credit in the release notes and advisory, unless you prefer otherwise.

## In scope

Problems in authdiff that put its users or the systems they test at risk, for
example:

- a request sent outside `scope.allowHosts` (including via redirects or the
  spec download),
- a destructive method sent without `--allow-destructive`,
- a token, cookie, API key or password written unmasked to logs, the terminal
  or any report,
- script execution or content injection in `report.html` from target
  responses or specs,
- a crash, hang or unbounded memory use caused by a malicious spec, response
  or rule file,
- TLS verification disabled without `--insecure`.

## Handling reports

Reports (`results.json`, `results.sarif`, `report.html`) contain request and
response evidence from the target, including other users' data when a finding
is real. Tokens and JWT-shaped strings are masked, but the data itself is
not. Treat reports as sensitive: authdiff writes them owner-only, and you
should not commit them, attach them to public issues or upload them anywhere
public.

## Out of scope

- Vulnerabilities in the **vuln-lab**: it is deliberately vulnerable. Never
  expose it to a network.
- Findings authdiff reports in *your* API: those are what the tool is for.
- Reports that require a malicious `authdiff.yaml` written by the same user
  who runs the scan (the config is trusted input).

## Release integrity

Release archives come with a `checksums.txt` (SHA-256). Verify a download
with `sha256sum -c checksums.txt --ignore-missing`. Signed releases and an
SBOM are planned.
