# vuln-lab

Deliberately vulnerable e-commerce REST API (FastAPI). It is the demo lab and the
end-to-end "expected findings" oracle for `authdiff`.

> **WARNING: do not run this in production and never expose it beyond localhost.**
> It contains intentional authorization bugs, a hard-coded JWT secret and leaks
> password hashes. All credentials here are fake, lab-only values.

## Run

```
docker compose up --build vuln-lab     # from the repo root; listens on 127.0.0.1:8000
```

Or locally:

```
cd vuln-lab
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Linux/macOS: .venv/bin/pip
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

OpenAPI spec: `http://127.0.0.1:8000/openapi.json`.

## Tokens

JWTs are deterministic (HS256, fixed secret, no `exp`). `python -m app.tokens` prints
`ADMIN_TOKEN`, `ALICE_TOKEN`, `BOB_TOKEN`; the committed copy lives in `examples/vuln-lab.env`.

## Expected findings

See [VULNERABILITIES.md](VULNERABILITIES.md) (V1-V8 plus the correctly protected negatives).

## Tests

```
cd vuln-lab && python -m pytest -q
```
