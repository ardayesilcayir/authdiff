# Web interface (`authdiff ui`)

`authdiff ui` starts a local web interface that drives the same engine as
`authdiff scan`. It covers the whole flow without YAML, environment variables
or the terminal: target, endpoints, profiles, safety settings, plan (dry run),
live scan, results, false-positive triage and export. The interface is in
English and Turkish.

```sh
authdiff ui                      # http://127.0.0.1:7465, opens the browser
authdiff ui --port 8080 --no-open
authdiff ui --projects-dir ./authdiff-projects
make ui                          # go run ./cmd/authdiff ui, from a checkout
```

| Flag | Default | Meaning |
|---|---|---|
| `--port` | `7465` | First port to try on `127.0.0.1`. If it is busy, the next free one is used (up to 10 ports). |
| `--no-open` | off | Print the link but do not open the browser. |
| `--projects-dir` | see [Projects](#projects) | Where projects are saved. |

The terminal prints a link such as `http://127.0.0.1:7465/?key=<64 hex>`.
Open that link; the interface does not work without it. Ctrl-C stops a running
scan (its partial results are kept) and then the server.

## Flow

```
Home ─┬─ Scan the demo lab ────────────────────────────────────────▶ Plan ▶ Scan ▶ Results
      ├─ Set up a new project ─▶ 1 Target ▶ 2 Endpoints ▶ 3 Profiles ▶ 4 Settings ▶ Plan ▶ Scan ▶ Results
      └─ Projects ─▶ project ▶ edit settings / scan again / earlier runs / export
```

1. **Target**: base URL, the OpenAPI spec as an upload (10 MiB at most) or a
   URL, `allowHosts` (derived from the base URL, editable) and the
   authorization checkbox (`acknowledgeAuthorization`). You cannot continue
   without it.
2. **Endpoints**: the inventory from the spec; deselect endpoints or pick
   tags (becomes `filter.exclude` / `filter.tags`).
3. **Profiles**: one card per identity (role, auth type, credentials, owned
   IDs, identifiers) and an "admin, 2 users and anonymous" preset.
4. **Settings**: rate, concurrency, timeout, destructive mode, and under
   *Advanced* the similarity threshold, ignored fields, proxy, TLS verification
   and the authorization matrix.
5. **Plan**: the dry-run request plan grouped by rule, with the request count,
   an estimated duration and destructive requests marked.
6. **Scan**: live progress over Server-Sent Events (phase, requests sent,
   preliminary findings). *Stop the scan* cancels the scan and keeps partial
   results. Only one scan runs at a time.
7. **Results**: severity totals, the endpoint × profile heat map, the finding
   list with filters, finding detail with masked evidence, downloads of
   `results.json`, `results.sarif` and `report.html`, and the project's
   earlier runs.

Every wizard step saves the project, so you can leave and come back.

### Destructive mode

Destructive mode (`safety.allowDestructive`) is off by default. Turning it on
requires typing `anladım` or `I understand` in the confirmation field; the
server checks this for every project, the demo included, and the check repeats
each time the mode is turned on again. Destructive checks
change data on the target.

### False positives

On a finding's page, *Mark as false positive* asks for a reason and appends
`<finding id> # <reason>` to the project's `.authdiff-ignore`. The finding
moves to the suppressed section and stays suppressed in later scans, exactly
like `authdiff scan --ignore-file`.

## Demo

*Scan the demo lab* on the home page needs the bundled [vuln-lab](../vuln-lab/README.md) running
on `http://127.0.0.1:8000`; the home page checks it and shows the start
commands when it is not reachable. The interface never starts or stops the lab.

The demo creates (or reopens) the project `vuln-lab-demo` from the example
config and the lab's fake tokens embedded in the binary, and goes straight to
the plan. It starts in safe mode. To find the write-side vulnerabilities too,
turn on destructive mode in the settings; the lab's data changes, so restart
it afterwards (`make lab-restart`).

## Security model

The interface holds API credentials and can send requests to real systems, so
it is built for one user on one machine.

- **Loopback only.** The server listens on `127.0.0.1` and has no option to
  listen on any other address. Requests whose `Host` header is not
  `127.0.0.1:<port>` or `localhost:<port>` get `421` (DNS rebinding).
- **Session key.** Each start generates a random 32-byte key. The `?key=`
  link sets an `HttpOnly; SameSite=Strict; Path=/` cookie named
  `authdiff_session` and redirects to the same page without the key. Every
  request without that cookie gets `401`. Treat the printed link like a
  password: anyone who has it while the server runs can use the interface. A
  restart makes the old link and cookie useless.
- **Cookies and ports.** Browsers do not separate cookies by port, so the
  session cookie is also sent to other servers on `127.0.0.1` in the same
  browser (for example a dev server on `127.0.0.1:3000`). A local program you
  do not trust can therefore read the key from requests your browser makes to
  it. Close the interface when you are done, or use a separate browser
  profile.
- **CSRF.** Every state-changing request is a `POST` that must carry this
  server's `Origin` (or `Referer`) and the session's CSRF token; otherwise
  `403`.
- **Headers.** Every response has a strict Content-Security-Policy (no inline
  script, no external resources, no framing), `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
  Content from the target API (bodies, headers, spec paths) is escaped by
  `html/template` and only ever set as text by the page scripts.
- **Same safety as the CLI.** Scans use `pkg/authdiff` and the same transport:
  the host allow list, the authorization acknowledgement, the rate limit and
  the destructive-method block all apply.

### Credentials are not stored

Tokens, usernames and passwords are kept in the server's memory only. They are
never written to disk, to logs or to browser storage, and the server never
sends them back to the browser: a saved credential shows as `•••• ` plus its
last four characters, and leaving the field empty keeps the current value.
The saved config uses `${env:...}` placeholders instead.

The consequence: **after the server restarts, the credentials are gone.**
Opening a project then asks for the missing ones again. Alternatively set them
as environment variables before starting `authdiff ui`; a profile whose
variable is set needs nothing typed in:

```
AUTHDIFF_<PROFILE>_TOKEN
AUTHDIFF_<PROFILE>_USERNAME     # basic auth
AUTHDIFF_<PROFILE>_PASSWORD     # basic auth
```

`<PROFILE>` is the profile name in upper case with every character outside
`A-Z0-9` replaced by `_` (`staging-admin` → `AUTHDIFF_STAGING_ADMIN_TOKEN`).

The only exception is the demo project: the lab's tokens are fake and already
public in this repository, so they are written to its `demo-secrets.json`.

## Projects

Projects are saved under the user config directory unless `--projects-dir`
says otherwise:

| OS | Default projects directory |
|---|---|
| Linux | `$XDG_CONFIG_HOME/authdiff/projects` (usually `~/.config/authdiff/projects`) |
| macOS | `~/Library/Application Support/authdiff/projects` |
| Windows | `%AppData%\authdiff\projects` |

Directories are created with mode `0700` and files with `0600`. Project names
match `^[a-z0-9][a-z0-9-]{0,62}$`. One project looks like this:

```
<projects-dir>/<name>/
  project.json        # the project as the interface sees it (source of truth)
  authdiff.yaml       # generated config, credentials as ${env:...} placeholders
  spec.<yaml|json>    # an uploaded spec; a spec URL stays in the config
  .authdiff-ignore    # suppressed findings
  runs/<time>/        # results.json, results.sarif, report.html of each scan
```

`project.json` is the source of truth. The interface regenerates
`authdiff.yaml` from it when the settings form a valid config; **editing
`authdiff.yaml` in the project directory by hand is not picked up** by the
interface and is overwritten on the next save. Importing an existing
`authdiff.yaml` into the interface is not supported yet.

## Export for the CLI and CI

*Download project zip* on a project's page (also linked from the results)
downloads a zip with everything `authdiff scan`
needs, all files at the top level:

| File | Content |
|---|---|
| `authdiff.yaml` | The config, credentials as `${env:AUTHDIFF_...}` placeholders; an uploaded spec as the relative `spec.<ext>`. |
| `spec.<ext>` | The uploaded spec, if any. |
| `.authdiff-ignore` | The project's suppressed findings. |
| `.env.example` | One `NAME=` line per credential variable, without values. |
| `vuln-lab.env` | Demo project only: the lab's fake tokens. |

```sh
unzip my-api.zip -d my-api && cd my-api
export AUTHDIFF_ALICE_TOKEN=... AUTHDIFF_BOB_TOKEN=...   # names from .env.example
authdiff scan -c authdiff.yaml
```

The same config gives the same findings in the CLI and in the interface: both
run `pkg/authdiff` and the same engine.

## Not in the interface

- **Custom rules.** The interface runs the built-in rules only; `rules.dirs`
  and `rules.disable` are not written to its config. Use the CLI with
  `--rules` (see [writing-rules.md](writing-rules.md)).
- **Body templates (`bodies`), output settings and `failOn`.** Edit the
  exported `authdiff.yaml` and use the CLI.
- **ID harvest rules (`harvest`).** The interface has no harvest editor; the
  demo project keeps the example's rule. Add harvest rules to the exported
  `authdiff.yaml` and use the CLI.
- **Remote or shared use.** There is no multi-user mode and no way to expose
  the interface on the network.
