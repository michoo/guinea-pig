# dynamic/ — DAST benchmark target

An intentionally-vulnerable Express service. Unlike the `static/` fixtures (graded
by source-code scanners), this one is graded by **DAST** tools that probe a
*running* service over HTTP. Each route is annotated in code and in `openapi.yml`
with the CWE it exposes.

## Run

```bash
cd dynamic
npm install
npm start            # http://localhost:3000  (override with PORT=...)
```

## Endpoints & expected CWEs

| Method & path | CWE | Weakness |
|---|---|---|
| `GET /search?q=` | CWE-79 | Reflected XSS |
| `POST /login` | CWE-89 (+CWE-209) | SQL injection; verbose SQL errors |
| `GET /users?id=` | CWE-89 | SQL injection (reflected) |
| `GET /ping?host=` | CWE-78 | OS command injection |
| `GET /download?file=` | CWE-22 | Path traversal |
| `GET /redirect?url=` | CWE-601 | Open redirect |
| `GET /fetch?url=` | CWE-918 | SSRF (cloud metadata reachable) |
| `GET /set-cookie` | CWE-1004 / CWE-614 | Cookie without HttpOnly/Secure/SameSite |
| *(all responses)* | CWE-942 | `Access-Control-Allow-Origin: *` with credentials |

`GET /openapi.yml` serves the OpenAPI document so API scanners can import it.

## Scanning it

```bash
# nuclei
nuclei -target http://localhost:3000 -severity medium,high,critical

# OWASP ZAP (baseline / full / API-driven)
docker run --network host -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:3000 -r report.html
docker run --network host -t ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t http://localhost:3000/openapi.yml -f openapi -r report.html
```

To score a DAST run against the CWE annotations above, see `../benchmark/`
(`benchmark/run.py --sarif-dir <dir>` accepts SARIF/JSON from a DAST tool).

## ⚠️ Exposure

This service executes shell commands, runs unsanitized SQL, reads arbitrary
files, and performs server-side requests **by design**. It has **no
authentication**. Consequences if exposed:

- **Bind to loopback only.** Run behind `127.0.0.1`; never `0.0.0.0` on a shared
  or public host. The `/ping` route is a direct remote-code-execution primitive.
- **Isolate it.** Prefer a disposable container/VM with no cloud credentials and
  no access to an instance-metadata endpoint (the `/fetch` SSRF can reach
  `169.254.169.254`).
- **No real data.** The database is in-memory with dummy users; keep it that way.
- **Tear it down** after scanning. Do not leave it running.
- `node_modules/` and `package-lock.json` are git-ignored; install locally.
