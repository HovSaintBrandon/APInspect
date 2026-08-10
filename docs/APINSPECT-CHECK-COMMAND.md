# APInspect `check` — How It Works

## What it is

APInspect is an internal API security scanner. The `check` command runs a full security checklist against a **single live endpoint**, with no Postman collection or spec file required — you give it the URL, method, headers, and body on the command line, and it does the rest.

## Example run

```bash
apinspect check "https://ilm-hie.dha.go.ke/middleware/api/v1/tenants/token" \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=livia-health&client_secret=<CLIENT_SECRET>" \
  --ai \
  -o token-endpoint-report.json
```

This checked the DHA/SHA OAuth2 **token endpoint** used by our Livia ↔ HIE integration.

## What happens under the hood

1. **Request setup** — the URL is split into base URL + path, the method/headers/body are parsed from CLI flags, and any `-t/-u/-p/--auth-file` auth options are resolved into request headers.
2. **Checklist engine runs** — a fixed suite of deterministic checks fires against the endpoint (see table below). Each check independently sends its own request(s) and returns a verdict: `PASS`, `FAIL`, `WARN`, or `MANUAL` (needs a human to confirm — not a finding by itself).
3. **Optional AI pass (`--ai`)** — the actual request/response pair plus all deterministic check results are sent to an LLM (Cerebras), which is instructed to only report issues the evidence actually supports, and to produce a `summary` plus severity-rated `findings` with a risk explanation and a concrete mitigation each.
4. **Report written (`-o`)** — every check result (and the AI findings, if requested) is serialized to the JSON file so it can be diffed over time, attached to a ticket, or fed into CI gating (`--fail-on <severity>` on the `scan` command does this automatically).

## The checklist, mapped to the run above

| Check | What it does | Result on the token endpoint |
|---|---|---|
| `discovery/endpointDiscovery` | Confirms the endpoint is actually reachable (gets any 2xx/4xx/5xx back). | ✔ PASS |
| `discovery/httpMethods` | Probes `OPTIONS`, `HEAD`, `PUT`, `DELETE`, `PATCH`, `TRACE` to catch unexpectedly-enabled methods. | ✔ PASS |
| `authentication/authRequired` | Re-sends the request *without* auth to check the endpoint doesn't leak data unauthenticated. | ⚠ MANUAL — skipped because no `-t`/auth was supplied for *this* request (it's the login endpoint itself, so that's expected) |
| `misconfigurations/cors` | Sends `Origin: https://evil.com` and checks whether `Access-Control-Allow-Origin`/`-Credentials` reflect it back (classic CORS misconfig). | ✔ PASS |
| `misconfigurations/securityHeaders` | Grades response headers securityheaders.com-style (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.) A–F. | ✖ **FAIL — Grade F (0/100)** |
| `dataExposure/sensitiveData` | Scans the response body for patterns that look like secrets/PII (only runs on GETs; skipped here as this is a POST). | ✔ PASS |
| `dataExposure/sensitiveDataAI` | AI re-check of the same concern using richer context, when evidence was captured. | ⚠ MANUAL — needs `apinspect audit` first to capture evidence |
| `errorHandling/stackTrace` | Sends a deliberately malformed request and checks the error response doesn't leak stack traces/internal paths. | ✔ PASS |
| `rateLimiting/bruteForce` | Fires 10 parallel requests and checks whether any throttling (429s) kicks in. | ⚠ WARN — no rate limiting observed; flagged for manual confirmation |
| `injection/sqliXss` | Fuzzes body fields with `'`, `"`, `<script>`, `OR 1=1` and checks for reflected payloads or SQL error signatures. | ✔ PASS |
| `injection/pathTraversal` | Fuzzes body fields with `../../../etc/passwd`-style payloads and checks for leaked file contents. | ✔ PASS |

## The AI layer's findings (this run)

| Severity | Issue | Why it matters |
|---|---|---|
| **HIGH** | Missing security hardening headers | No CSP/HSTS/X-Frame-Options/X-Content-Type-Options — leaves the response vulnerable to clickjacking, MIME-sniffing, and downgrade attacks if ever rendered/proxied through a browser context. |
| **MEDIUM** | Sensitive data in JWT claims | The issued access token embeds internal identifiers (`tenant_id`, `clientHost`, `clientAddress`) — if the token leaks or is logged, it hands an attacker internal topology info. |
| **LOW** | Server header disclosure | `Server: APISIX/3.13.0` fingerprints the exact gateway + version, making it easier to look up known CVEs. |

The AI is instructed to never invent findings: it's given strict evidence rules (e.g. a 4xx isn't proof auth is broken; `MANUAL`/`TO BE CONFIRMED` checks can't be restated as confirmed vulnerabilities) so what you see above is grounded in the actual response, not a guess.

## Why this matters for the team

- **Zero setup per endpoint** — no collection file, no environment config; just the curl-equivalent flags you already know.
- **Consistent baseline every run** — same 11 deterministic checks every time, so results are comparable across endpoints and over time.
- **AI adds judgment, not noise** — the deterministic layer proves *what* happened; the AI layer explains *why it matters* and *what to do about it*, with severities we can triage against.
- **CI-ready** — the JSON report (`-o token-endpoint-report.json`) is the same shape `scan --fail-on <severity>` consumes, so this can gate a pipeline once we're ready.

## Suggested next step

Run `apinspect audit` against the same request first to populate response evidence, then re-run `check --ai` — that unlocks the `dataExposure/sensitiveDataAI` check, which is currently sitting at MANUAL for lack of captured evidence.
