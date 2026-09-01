<div align="center">

# APInspect
### AI-Driven API Security Checklist Scanner

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-v14+-green.svg)](https://nodejs.org/)
[![Security](https://img.shields.io/badge/Security-OWASP%20API%20Top%2010-red.svg)](https://owasp.org/www-project-api-security/)

**A checklist-driven security scanner that verifies specific security controls, endpoint-by-endpoint, across REST, GraphQL, and gRPC APIs — with an AI layer that decides what applies, builds the attack, and judges the result.**

</div>

---

## Table of Contents

- [The Core Idea](#the-core-idea)
- [How It Works](#how-it-works)
- [Supported API Styles](#supported-api-styles)
- [What Gets Checked](#what-gets-checked)
  - [Security Header Grading](#security-header-grading)
- [Installation](#installation)
- [Configuration](#configuration)
- [Input Files You Need to Prepare](#input-files-you-need-to-prepare)
- [Commands](#commands)
- [Authentication](#authentication)
- [Running Locally — Walkthrough](#running-locally--walkthrough)
- [Using It in a Git Workflow](#using-it-in-a-git-workflow)
- [Embedding in a CI/CD Pipeline](#embedding-in-a-cicd-pipeline)
- [Exit Codes](#exit-codes)
- [Reports](#reports)
- [Project Layout](#project-layout)
- [Troubleshooting](#troubleshooting)

---

## The Core Idea

Most API scanners are pattern-matchers: they fire a fixed set of payloads at every endpoint and hope something sticks. APInspect works differently — it runs a **security checklist** (34 items across 14 categories, modeled on the OWASP API Security Top 10 plus business-logic and infrastructure concerns) and, for every single endpoint, decides:

1. **Does this check even apply here?** (an `AUTH-01` auth-enforcement check doesn't make sense against a public health-check endpoint; a `GQL-*` introspection check doesn't make sense against a REST endpoint)
2. **If it applies, what's the smallest, safest request that actually tests it?** (a synthesized probe, tailored to that endpoint's shape — not a generic payload)
3. **Did the response prove the control holds, or does it not?** (a verdict, with a confidence score, evidence cited, and a bias toward flagging "not sure" rather than guessing)

Checks that don't need judgment (is TRACE enabled, is HSTS present, is a stack trace leaking) are handled deterministically by hardcoded modules — no AI, no ambiguity. Checks that require reasoning about intent (is this token *actually* validated server-side, can I access another user's object, does this workflow allow skipping a required step) go through a three-stage AI pipeline: **applicability → probe synthesis → verdict classification**. Every AI verdict below a confidence threshold is downgraded to `TO BE CONFIRMED` rather than reported as a false certainty — the tool is designed to fail toward "flag for a human," never toward silent false negatives.

The result is a per-endpoint, per-check report you can read as a checklist, gate a CI/CD pipeline on, or hand to a pentester as a head start.

---

## How It Works

```
 API Definition                Discovery              Checklist Engine                 Report
 (Postman / OpenAPI /    ──▶   (which endpoints   ──▶  (per endpoint, per      ──▶     (JSON / CSV /
  GraphQL SDL / .proto)        are reachable, what      check: applicable? AI          FALCON review
                                methods work)            probe → verdict)               spreadsheet)
```

1. **Parse** — the input file is auto-detected (Postman collection, OpenAPI/Swagger, GraphQL SDL or live introspection URL, gRPC `.proto`) and normalized into a flat list of endpoints.
2. **Style resolution** — if the input is ambiguous (Postman/OpenAPI/raw JSON could describe REST or a GraphQL endpoint fronted by REST-shaped tooling), you're prompted to confirm the architecture style, or you supply it up front with `--style`. Unambiguous inputs (`.graphql`, `.proto`, a live GraphQL URL) skip the prompt.
3. **Discovery** — a lightweight pass hits each endpoint to harvest path variables and confirm reachability before the real checks run.
4. **Engine execution** — for every endpoint:
   - Checklist items whose `applies_to` doesn't match the resolved protocol are excluded immediately (no wasted AI calls).
   - The **Applicability Engine** asks the model, in one batched call per endpoint, which of the remaining items are relevant.
   - Items mapped to a hardcoded module (`maps_to_check`) run deterministically.
   - Items requiring judgment (`requires_ai_probe`) go through the **Probe Synthesizer** — one batched call building a context-aware HTTP request for every such item on the endpoint at once — then, after each request actually fires, the **Verdict Classifier** judges all the surviving responses in one more batched call (cites evidence, assigns confidence). Both stages batch per endpoint the same way applicability does, so a full endpoint costs roughly 3 AI calls total instead of up to 1 + 2×(items requiring judgment).
5. **Report** — every result (`PASS` / `FAIL` / `WARN` / `N/A` / `MANUAL` / `TO BE CONFIRMED`) is written out with severity, category, and — for AI-driven checks — the full evidence trail (request, response, reasoning).

If the multi-role auth flow is used, the entire cycle above repeats once per role (e.g. `student`, `admin`), so you get a same-endpoint comparison across privilege levels for free.

---

## Supported API Styles

| Style   | Input                                                                | Detected by |
|---------|-----------------------------------------------------------------------|-------------|
| REST    | Postman collection, internal JSON, OpenAPI/Swagger (`.json`/`.yaml`/`.yml`) | `openapi`/`swagger` key, or Postman `info._postman_id` — style confirmed via `--style` or interactive prompt |
| GraphQL | SDL file (`.graphql`/`.gql`) or a live endpoint URL (introspection)    | file extension, or `http(s)://` target — unambiguous, no prompt |
| gRPC    | `.proto` file + `-b host:port` target                                 | `.proto` extension — unambiguous, no prompt |

Style-specific checks live under `src/checks/graphql/` (introspection exposure, query-depth/complexity DoS) and `src/checks/grpc/` (metadata auth stripping, TLS enforcement, reflection, message-size limits). The general HTTP-semantic checks (auth, CORS, headers, injection, rate limiting) apply to both REST and GraphQL, since GraphQL runs over plain HTTP; gRPC is excluded from those since it has no HTTP verbs, `OPTIONS`, or `TRACE` to test.

---

## What Gets Checked

34 checklist items across these categories — full detail in `src/config/checklist.json`:

| Category | Examples |
|---|---|
| Discovery | Endpoint reachability, dangerous HTTP methods (`TRACE`) |
| Authentication | Enforcement, server-side token validation, broken object-level authorization (BOLA) |
| Injection | SQLi/XSS fuzzing, path traversal, SSRF-style internal-URL rejection |
| Data Exposure | Emails, SSNs, private keys, AWS keys, JWTs, Stripe/Google API keys, over-fetching |
| Misconfigurations | CORS wildcard/reflected-origin, security-header grading (securityheaders.com-style A+–F, see below), version disclosure |
| Error Handling | Stack traces, verbose framework errors |
| Rate Limiting | Brute-force burst testing, header-spoofing bypass attempts |
| Mass Assignment | Privileged-field injection (`role`, `isAdmin`, `ownerId`) |
| Business Logic | Workflow-step skipping, transaction/quantity limits, out-of-range values |
| Third-Party Integration | Callback/webhook URL validation |
| CI/CD & Infrastructure | Leaked credentials, exposed debug/staging endpoints |
| GraphQL Security | Introspection exposure, query-depth DoS |
| gRPC Security | Metadata auth stripping, TLS enforcement, reflection, message-size limits |
| WebSocket Security | Auth on upgrade, message-level authorization |

### Security Header Grading

`misconfigurations/securityHeaders` doesn't just check presence — it grades the response headers the way [securityheaders.com](https://securityheaders.com) does, from a rule set APInspect owns outright (`src/config/securityHeaderRules.json`), scored by `src/core/headerGrader.js`:

- **Weighted scoring, not a naive count** — each header (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) contributes a weight toward a 0–100 score, mapped to a letter grade (`A+` down to `F`).
- **Value quality, not just existence** — a present-but-weak header still loses points: `unsafe-inline`/`unsafe-eval`/wildcard sources in CSP, HSTS `max-age` under 6 months or missing `includeSubDomains`, `X-Frame-Options` set to anything other than `DENY`/`SAMEORIGIN`, `Referrer-Policy: unsafe-url`, etc.
- **Fingerprinting/leak headers are penalized** — `Server`, `X-Powered-By`, `X-AspNet-Version` subtract from the score if present, since they aid reconnaissance without protecting anything.
- **Deprecated headers are informational only** — `X-XSS-Protection` no longer affects scoring; modern browsers ignore it.
- Every finding carries a concrete `recommendation` (e.g. the exact header/value to add), returned in `details.findings` on the check result.
- `misconfigurations/securityHeaders` maps the letter grade back to the engine's `PASS`/`WARN`/`FAIL` contract (`A`/`A+`/`B` → `PASS`, `C`/`D` → `WARN`, `E`/`F` → `FAIL`) so it plugs into `--fail-on` gating like any other check.

Grading logic lives entirely in this repo — no third-party API, no rate limits, editable rule set. See the standalone [`apinspect headers <url>`](#apinspect-headers-url--single-url-header-grade-no-scan-required) command below to run just this check against a single URL.

---

## Installation

### Prerequisites
- Node.js v14+
- npm
- An [OpenRouter](https://openrouter.ai) API key (only required for `--checklist` mode — the AI-driven pipeline)

### Install

```bash
git clone <this-repo-url>
cd APInspect
npm install
npm link          # optional — exposes the `apinspect` command globally
```

Without `npm link`, run it as `node src/cli/index.js <command>` from the repo root, or `node /path/to/APInspect/src/cli/index.js <command>` from anywhere.

---

## Configuration

Checklist mode needs an OpenRouter API key. Copy the example env file and fill it in:

```bash
cp .env.example .env
```

```env
# .env
OPENROUTER_API_KEY=sk-or-v1-your_key_here
```

`.env` is gitignored — never commit real keys. In CI, inject this as a secret environment variable instead (see [CI/CD](#embedding-in-a-cicd-pipeline)).

Model and confidence thresholds are tunable in `src/config/aiConfig.js` — don't hardcode the model ID anywhere else.

#### Model fallback — tiered router

`AI_MODEL` in `aiConfig.js` is the primary model. `AI_MODEL_TIERS` is a pool of backup models split into groups of up to 3 — OpenRouter hard-caps its `models` fallback field at 3 entries total (a 4th 400s the whole request), so more than 3 candidates has to become more than one tier rather than one flat list. `src/core/modelTierRouter.js` picks which tier goes on the request: tier 0 by default, rotating to tier 1 once tier 0 looks unhealthy (`AI_MODEL_ROUTER_CONFIG` in the same file tunes the failure-count and latency thresholds for "unhealthy"), and looping back to tier 0 if tier 1 also goes bad. See [docs/MODEL-TIER-ROUTER-PLAN.md](docs/MODEL-TIER-ROUTER-PLAN.md) for the full design. Set `AI_MODEL_TIERS` to a single one-model tier (`[[AI_MODEL]]`) to disable rotation and fail closed on the primary alone — do this for a run whose result needs to be reproducible against one known model.

`AI_PROVIDER_POLICY` in the same file is sent as OpenRouter's `provider` field on every call — `require_parameters: true` stops a fallback provider from silently ignoring `response_format: json_object` and returning prose instead of JSON, and `data_collection: 'deny'` opts every provider that ends up serving a call out of retaining the live scan data this tool sends (auth tokens, PII, internal error bodies from whatever you're scanning) for training. The stricter `zdr: true` (require a zero-data-retention *host*, not just a no-training policy) is commented out by default — it 404s ("No endpoints found matching your data policy") for any model whose providers aren't ZDR-enrolled, which was every model in the default config as of this writing. Confirm your target model actually has a ZDR-eligible host before uncommenting it.

Picking free-tier models to put in `AI_MODEL_TIERS` is trickier than it looks — verified live against the real API, most of OpenRouter's free catalog isn't actually usable under the policy above: some models are only reachable through agentic-harness integrations, not the plain chat completions API; some have zero providers that support `require_parameters` + JSON mode at all; and some specifically require opting *into* training-data collection as the price of free access, which directly conflicts with `data_collection: 'deny'`. None of these clear up on retry — the comments above `AI_MODEL_TIERS` list exactly which excluded models hit which failure and why, so read those before adding a new candidate.

When a fallback model actually answers a call, you'll see `[OpenRouterClient] Response served by fallback model "...", not requested "..."` in the log (once per distinct fallback model per run) — a different model can mean different tone and JSON reliability, so treat findings from a run that shows this line with a bit more scrutiny. A tier rotation logs as `[ModelTierRouter] Tier N unhealthy/is slow — rotating to tier M: [...]`.

---

## Input Files You Need to Prepare

Everything else in this tool — discovery, style resolution, the checklist run, per-role comparisons — is derived from two files you provide. Neither is generated for you; you bring them from your own API project.

### 1. The API definition file (required)

This is what `parser.js` reads to build the attack surface (`config.endpoints`, `config.base_url`, `config.protocol`). Bring **whichever of these you already have** — you don't need to write a new format:

| You already have... | Give APInspect... | What happens |
|---|---|---|
| A Postman collection you export from Postman | the `.json` export, unmodified | `extractPostmanEndpoints` walks every `item`/folder and flattens it to `{ path, methods }`. You'll be asked (or pass `--style`) to confirm REST vs. GraphQL, since a Postman file alone doesn't say which. If the collection has top-level folders, you'll also be asked which one(s) to scan (or pass `--folder`) — see below. |
| An OpenAPI/Swagger spec | the `.json`/`.yaml`/`.yml` file | `openapiAdapter` parses `paths` into endpoints automatically. |
| A GraphQL schema | a `.graphql`/`.gql` SDL file, or just the live endpoint URL | `graphqlAdapter` builds endpoints from the schema, or introspects the live URL directly — no manual endpoint list needed either way. |
| A gRPC service | the `.proto` file + `-b host:port` | `grpcAdapter` reflects the service definition into endpoints (one per RPC method). |
| None of the above — you just want to hand-list endpoints | a small internal JSON file (format below) | Used as-is once normalized. |

**Internal JSON format** (the fallback — write this only if you have no Postman/OpenAPI/GraphQL/proto file to point at):

```json
{
  "base_url": "https://api.example.com",
  "protocol": "rest",
  "auth": {
    "type": "bearer",
    "token": "placeholder-token"
  },
  "endpoints": [
    { "path": "/posts/1", "methods": ["GET"] },
    { "path": "/users/1", "methods": ["GET"] },
    { "path": "/invalid-endpoint-test", "methods": ["GET"] }
  ]
}
```

See `examples/api-sample.json` for a runnable copy of this. `protocol` is optional here too — omit it and you'll get the same interactive style prompt as a Postman file.

### 2. The auth file (optional, but required for any real finding)

Without it, the scan runs unauthenticated end-to-end — useful for confirming public endpoints are properly locked down (`AUTH-01`), but you'll get `MANUAL`/`TO BE CONFIRMED` on every check that needs a valid session (BOLA, mass assignment, business logic, data exposure post-auth). To get real `PASS`/`FAIL` verdicts, hand APInspect a way to log in as one or more roles.

This is a file **you write yourself**, pointed at your own auth system — there's no fixed schema APInspect ships with, because every API's login flow is different. Two shapes are supported:

**Shape A — shared login endpoint, per-role payload** (use when every role logs in the same way, just with different credentials):

```json
{
  "login_endpoint": "https://api.example.com/auth/login",
  "method": "POST",
  "token_path": "data.access_token",
  "roles": [
    { "name": "student",  "payload": { "email": "student@test.com", "password": "Test123!" } },
    { "name": "classrep", "payload": { "email": "rep@test.com", "password": "Test123!" } }
  ]
}
```

- `login_endpoint` / `method`: how APInspect logs each role in before the scan starts.
- `token_path`: dot-path into the login response JSON where the bearer token lives (e.g. `data.access_token` → `res.data.data.access_token`).
- `roles[].payload`: the exact request body your login endpoint expects for that role.

**Shape B — mixed auth types per role** (use when roles authenticate differently — some via login+JWT, some via static Basic Auth credentials, as with the `lecturer`/`admin` roles in the walkthrough above):

```json
{
  "roles": [
    {
      "name": "student",
      "auth_type": "bearer",
      "login_endpoint": "https://api.example.com/auth/login",
      "method": "POST",
      "token_path": "token",
      "payload": { "email": "student@test.com", "password": "Test123!" }
    },
    {
      "name": "lecturer",
      "auth_type": "basic",
      "credentials": { "username": "REG-001-LECT", "password": "Test123!" }
    }
  ]
}
```

How this ties into the scan: for **each role** in the file, APInspect logs in (or builds the Basic Auth header), then runs the **entire checklist against every endpoint** as that role — producing one full report per role (`report.student.json`, `report.lecturer.json`, ...) plus a combined run. This is what makes checks like `AUTH-03` (BOLA — access another user's object) and mass-assignment checks meaningful: the AI probe synthesizer can construct a request as `student` that tries to read/modify data belonging to another user, and the verdict classifier judges whether the server actually blocked it.

Keep this file out of git — see [Using It in a Git Workflow](#using-it-in-a-git-workflow) for where to put it instead.

---

## Commands

### `apinspect scan <file>` — the primary command

Runs the full active security scan.

```bash
apinspect scan <file> [options]
```

| Option | Description |
|---|---|
| `-t, --token <token>` | Bearer token for authentication |
| `-u, --username <user>` / `-p, --password <pass>` | Basic Auth credentials |
| `-b, --base-url <url>` | Base URL for REST/GraphQL, or `host:port` for a gRPC target |
| `--style <rest\|graphql\|grpc>` | Architecture style. Skips the interactive prompt for ambiguous inputs. |
| `-f, --folder <name...>` | Restrict a Postman collection scan to specific top-level folder(s) by name. Skips the interactive folder-picker prompt shown when the collection has folders. |
| `--auth-file <path>` | Multi-role auth config — see [Authentication](#authentication) |
| `--checklist` | Enable AI-driven checklist mode (recommended — otherwise a smaller hardcoded legacy check list runs) |
| `--cache <path>` | Persist AI applicability/probe decisions to a file — reused on the next run against an unchanged target, and committable for deterministic CI runs |
| `-o, --output <path>` | Report path — `.json`, `.csv`, or `.falcon.csv` (review spreadsheet format). Omit it and the report is written to `reports/<collection-or-folder-name>/report-<timestamp>.json` — the directory tracks the collection (or the `-f/--folder` name, when scoped) so repeat scans of the same input land together, while the timestamped file name keeps every run from overwriting the last. |
| `--fail-on <severity>` | Exit code 1 if any confirmed finding meets/exceeds this severity: `critical`, `high`, `medium`, `low`, `info` |
| `--fail-on-tbc` | Also count `TO BE CONFIRMED` findings toward `--fail-on` (requires `--fail-on`) |
| `--config <path>` | Run in **declarative mode** instead — mutually exclusive with a positional `<file>` and every option above. See below. |

### `apinspect scan --config <path>` — declarative mode (CI-safe, zero LLM calls)

A second way to run `scan`, coexisting with the file-driven mode above (pick one per invocation —
positional file *or* `--config`, never both). Fully config-driven: every check, endpoint, and
authorized host is fixed by `apinspect.config.yaml` before the scan starts, with no LLM call
anywhere in the path — the only mode meant to gate a CI pipeline on. Full contract, config format,
check list, and exit codes: [docs/APINSPECT-DECLARATIVE-MODE.md](docs/APINSPECT-DECLARATIVE-MODE.md);
example config: [apinspect.config.example.yaml](apinspect.config.example.yaml).

```bash
apinspect scan --config apinspect.config.yaml
```

### MCP server — local triage, never a gate

A separate entrypoint (`src/mcp/server.js`, not part of the `apinspect` CLI binary) sharing the
same core as declarative mode above. Five tools — `list_runs`, `get_findings`, `explain_finding`,
`diff_runs` (all read-only, only ever reading what `scan --config` already wrote), and `run_check`
(the only one that touches the target; rate-limited, session-capped, and audit-logged). No tool
here can produce a pass/fail verdict — every result is tagged `"gating": false`. Full contract,
constraints, and registration instructions:
[docs/APINSPECT-MCP-SERVER.md](docs/APINSPECT-MCP-SERVER.md).

### `apinspect audit <file>` — Newman-backed response audit

Runs a Postman collection through Newman and scans the captured responses for leaked secrets. Checklist items like `DATA-02` read from this evidence store — run `audit` before `scan --checklist` if you want those items resolved instead of `MANUAL`.

```bash
apinspect audit <file> [-e <environment.json>]
```

### `apinspect analyze <file>` — static analysis, zero requests

Inspects a Postman collection's structure for definitional issues without touching the network.

```bash
apinspect analyze <file>
```

### `apinspect headers <url>` — single-URL header grade, no scan required

Runs just the security-header grader (see [Security Header Grading](#security-header-grading)) against one URL, without needing an API definition file, discovery, or the checklist engine. Useful for a quick check against a base URL before committing to a full scan.

```bash
apinspect headers https://api.example.com
```

Follows redirects and grades the **final** destination, not the `3xx` hop. Supports the same auth options as `scan`:

| Option | Description |
|---|---|
| `-t, --token <token>` | Bearer token for authentication |
| `-u, --username <user>` / `-p, --password <pass>` | Basic Auth credentials |
| `--auth-file <path>` | Same auth-file format as `scan` — see [Authentication](#authentication) (only the `default`/first role is used) |
| `-o, --output <path>` | Write the grade + findings as JSON |
| `-AI, --ai` | Ask the AI to explain the risk and mitigation for each missing/weak/leaking header |

The grade is color-coded in the terminal, green (`A+`/`A`) fading through yellow/orange (`B`–`D`) to red (`E`/`F`), same at-a-glance read as securityheaders.com.

Example output:

```
Grade: B  (69/100)
✔ Strict-Transport-Security: present and correctly configured.
⚠ Content-Security-Policy: present but weak: allows 'unsafe-inline'. → Add a Content-Security-Policy with an explicit default-src and no unsafe-inline/unsafe-eval, e.g. default-src 'self'
⚠ Permissions-Policy: missing. → Add a Permissions-Policy restricting sensitive features, e.g. geolocation=(), camera=(), microphone=()
⚠ Server: discloses server implementation details. → Remove or generalize the Server header
```

With `--ai`, each weak/missing/leaking header additionally gets an AI-generated **Risk** and **Mitigation** writeup, appended to the JSON output under `aiAnalyses` when `-o` is used.

### `apinspect check <url>` — full check sweep against a single live endpoint

Runs the same hardcoded check suite as `scan` (discovery, HTTP method fuzzing, auth enforcement, CORS, security headers, sensitive data exposure, stack traces, rate limiting, SQLi/XSS and path-traversal fuzzing) against **one** endpoint — no Postman collection, OpenAPI spec, or discovery step required. Pass everything the request needs directly on the command line.

```bash
apinspect check <url> [options]
```

| Option | Description |
|---|---|
| `-X, --method <method>` | HTTP method to use (default `GET`) |
| `-H, --header <header...>` | Extra request header as `"Key: Value"` — repeatable |
| `-d, --data <body>` | Request body — a JSON string, or `@path/to/file.json` |
| `-t, --token <token>` | Bearer token for authentication |
| `-u, --username <user>` / `-p, --password <pass>` | Basic Auth credentials |
| `--auth-file <path>` | Same auth-file format as `scan` — see [Authentication](#authentication) (only the `default`/first role is used) |
| `-o, --output <path>` | Write check results (and AI findings, if `--ai`) as JSON |
| `-AI, --ai` | Send the live request/response and check results to the AI for an overall risk summary and mitigations |

```bash
apinspect check https://api.example.com/users/42 -X POST \
  -H "X-Api-Version: 2" \
  -d '{"name":"test"}' \
  -t "eyJhbGciOi..." \
  --ai
```

With `--ai`, the endpoint is hit a second time and the request/response plus the deterministic check results are handed to the AI, which returns a summary and a list of findings — each with a severity, the concrete risk, and a mitigation technique — printed after the standard check output.

### `apinspect jwt <token>` — JWT decode, header/claims audit, and forgery testing

Decodes a bearer JWT and audits it across the header, claims, and signature — then actively tries to forge a token the server will still accept. No collection or spec file needed; just the token.

```bash
apinspect jwt <token> [options]
```

| Option | Description |
|---|---|
| `-e, --endpoint <url>` | Authenticated endpoint to fire forged tokens at. Without this, tokens are constructed and printed but never sent. |
| `-X, --method <method>` | HTTP method to use against `--endpoint` (default `GET`) |
| `-H, --header <header...>` | Extra request header as `"Key: Value"` — repeatable |
| `--public-key <path>` | PEM public key file — enables the RS/ES/PS → HS256 algorithm-confusion attack |
| `--wordlist <path>` | Newline-delimited wordlist for HMAC secret cracking, merged with the built-in common-secrets list |
| `-o, --output <path>` | Write the decoded token, findings, forged tokens, and live results as JSON |
| `-AI, --ai` | Ask the AI for a risk analysis and mitigations across everything found |

What it does, in order:
1. **Decodes** the header and payload (no verification — this is a read, not a trust decision).
2. **Header analysis** — flags `alg: none`, unrecognized algorithms, an injectable `kid`, and SSRF-prone `jku`/`x5u`/embedded `jwk`.
3. **Claims analysis** — flags a missing/absent `exp`, an unusually long lifetime, missing `iss`/`aud`/`jti`, and sensitive-looking data sitting in the payload (it's base64, not encrypted).
4. **Weak-secret cracking** — for `HS256`/`384`/`512` tokens, tries the signature against a built-in common-secrets list (extendable with `--wordlist`). A hit means the token can be forged outright.
5. **Forges tokens**: `alg=none` (signature stripped, 3 casing variants), RS/ES/PS→HS256 algorithm confusion (if `--public-key` is given), `kid` injection (path traversal / SQLi payloads), and — if the secret was cracked — a re-signed token with any recognizable privilege claim (`role`, `isAdmin`, `scope`, etc.) escalated and `exp` pushed out 10 years.
6. **Tests live**, if `--endpoint` is given: sends each forged token, plus a no-auth and original-token baseline, and classifies each as `accepted` / `rejected` / `inconclusive` (the endpoint doesn't enforce auth at all, so nothing is attributable to the forgery).

```bash
apinspect jwt "eyJhbGciOi..." \
  --endpoint https://api.example.com/account/profile \
  --public-key ./keys/jwt_public.pem \
  --ai
```

Any forged token the live test marks `accepted` is surfaced as a `critical` finding — that's a demonstrated auth bypass, not a theoretical one. With `--ai`, everything (decoded header/payload, static findings, live results) is handed to the AI for a prioritized risk summary and specific mitigations, printed after the deterministic output and included in the JSON output under `aiAnalysis` when `-o` is used.

---

## Authentication

Four ways to authenticate a scan, in priority order:

**1. Single bearer token**
```bash
apinspect scan api.json -t "eyJhbGciOi..." -b https://api.example.com
```

**2. Single Basic Auth pair**
```bash
apinspect scan api.json -u admin -p "s3cr3t" -b https://api.example.com
```

**3. Multi-role auth file** — scans once per role, so you get the same checklist run against `student`, `admin`, etc., and can compare privilege boundaries directly:

```json
{
  "login_endpoint": "https://api.example.com/auth/login",
  "method": "POST",
  "token_path": "data.access_token",
  "roles": [
    { "name": "student",  "payload": { "email": "student@test.com", "password": "..." } },
    { "name": "classrep", "payload": { "email": "rep@test.com", "password": "..." } }
  ]
}
```

Or, per-role with mixed auth types (no shared login endpoint needed):

```json
{
  "roles": [
    { "name": "student",  "auth_type": "bearer", "login_endpoint": "https://api.example.com/auth/login", "payload": {"email": "s@test.com", "password": "..."} },
    { "name": "lecturer", "auth_type": "basic",  "credentials": { "username": "REG-001-LECT", "password": "..." } }
  ]
}
```

```bash
apinspect scan api.json --auth-file apinspect_auth.json --checklist -b https://api.example.com
```

**4. No auth** — scans unauthenticated; `authRequired`/`AUTH-01` still verifies the API correctly rejects it.

---

## Running Locally — Walkthrough

```bash
# 1. Install
git clone <repo-url> && cd APInspect && npm install && npm link

# 2. Configure the AI key (checklist mode only)
cp .env.example .env && sed -i '' 's/your_key_here/YOUR_REAL_KEY/' .env

# 3. Run a basic scan against the bundled example
apinspect scan examples/api-sample.json

# 4. Run the full checklist-driven scan against a real target
apinspect scan my-collection.json \
  --checklist \
  --base-url https://api.example.com \
  --auth-file apinspect_auth.json \
  --style rest \
  -o reports/scan.json

# 5. Gate on severity (useful before wiring into CI)
apinspect scan my-collection.json --checklist --base-url https://api.example.com \
  --fail-on high
echo "exit code: $?"
```

Human-readable review spreadsheet instead of JSON:

```bash
apinspect scan my-collection.json --checklist -b https://api.example.com -o reports/review.falcon.csv
```

---

## Using It in a Git Workflow

A practical loop for scanning a branch before opening a PR:

```bash
# On your feature branch, after making an API change
apinspect scan collections/api.postman_collection.json \
  --checklist \
  --auth-file .secrets/apinspect_auth.json \
  --base-url https://staging.internal.example.com \
  --cache .apinspect-cache.json \
  -o reports/pre-pr-scan.json

# Review reports/pre-pr-scan.json (or open the .falcon.csv variant) —
# fix anything Critical/High before pushing.
git add reports/pre-pr-scan.json   # optional — commit as PR evidence
git commit -m "security: attach pre-PR APInspect scan"
git push
```

Recommendations:
- **Commit `--cache` output** (e.g. `.apinspect-cache.json`) alongside the branch if you want reviewers to see byte-identical AI decisions on re-run — otherwise probe synthesis has a small amount of run-to-run variance (temperature `0.1`).
- **Never commit `.env`** or raw auth files with real credentials — keep `apinspect_auth.json` in a gitignored `.secrets/` directory or pull credentials from your secret manager at scan time.
- Add `reports/` to `.gitignore` (already the default) unless you deliberately want scan output tracked as PR evidence.
- Consider a `pre-push` git hook that runs a fast, unauthenticated `--checklist` pass with `--fail-on critical` so nothing egregious reaches a PR at all.

---

## Embedding in a CI/CD Pipeline

APInspect is designed to be a **hard security gate**: it exits non-zero when a qualifying finding is present, so any CI system that checks exit codes works out of the box. See [Exit Codes](#exit-codes) below for the full contract — code `3` (infrastructure failure) is deliberately distinct from code `1` (real findings) so you don't silently pass a build just because the AI backend timed out.

### GitHub Actions

```yaml
# .github/workflows/api-security.yml
name: API Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  apinspect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install APInspect
        run: |
          git clone <apinspect-repo-url> apinspect-tool
          cd apinspect-tool && npm ci

      - name: Run security scan
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          node apinspect-tool/src/cli/index.js scan collections/api.postman_collection.json \
            --checklist \
            --style rest \
            --base-url ${{ secrets.STAGING_API_URL }} \
            --auth-file ci/apinspect_auth.json \
            --cache apinspect-tool/.apinspect-cache.json \
            --fail-on high \
            -o reports/scan.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: apinspect-report
          path: reports/
```

#### Using GitHub Secrets for the API key and target URL

Both values the scan needs at runtime — `OPENROUTER_API_KEY` and the target's base URL — are ordinary strings the tool reads from an environment variable and a CLI flag respectively, which is exactly what GitHub Secrets exists to inject. Nothing tool-specific is required to make this work:

- `OPENROUTER_API_KEY` is read straight from `process.env` (`src/core/openrouterClient.js`) — the workflow above sets it under `env:` on the scan step from `${{ secrets.OPENROUTER_API_KEY }}`, so the real key is never written into the workflow file, never appears in `git log`, and is masked in the Actions log output automatically.
- `${{ secrets.STAGING_API_URL }}` is substituted by GitHub *before* the shell command runs, so it's passed to `--base-url` like any other value — APInspect never has to know it came from a secret.
- The same applies to anything referenced by `--auth-file`: if the JSON file itself contains real credentials, don't commit it — check it into a private path outside the repo, restore it from a secret at job start (see the `Write a secret to a file` pattern below), or better, keep the file structure in the repo but store the actual `password`/`payload` values as their own secrets and template them in with `envsubst` or a small `sed` step before the scan runs.

To set these up once, in the repo's **Settings → Secrets and variables → Actions**:

```
OPENROUTER_API_KEY = <your real OpenRouter key>
STAGING_API_URL    = https://staging.internal.example.com
```

If your `auth-file` needs to carry a real secret (e.g. a test account password), a common pattern is to keep a *templated* file in the repo and materialize it in CI:

```yaml
      - name: Materialize auth file from secrets
        run: |
          envsubst < ci/apinspect_auth.template.json > ci/apinspect_auth.json
        env:
          STUDENT_PASSWORD: ${{ secrets.STUDENT_PASSWORD }}
          LECTURER_PASSWORD: ${{ secrets.LECTURER_PASSWORD }}
```

where `ci/apinspect_auth.template.json` (safe to commit) contains `"password": "$STUDENT_PASSWORD"` in place of a literal value. This keeps every credential the scan needs — the AI key, the target URL, and any login passwords — out of the repository entirely, while still giving APInspect a normal file path and normal env vars to read at scan time. The tool has no awareness of secrets managers; it just consumes `process.env` and CLI arguments, which is what makes it drop into any CI system's existing secret-injection mechanism without modification.

Key points for CI:
- Always pass `--style` explicitly in CI — with no TTY attached, the interactive style prompt for ambiguous inputs (Postman/OpenAPI/raw JSON) will hang the job waiting for input it will never receive.
- If the Postman collection has top-level folders, also pass `--folder` explicitly in CI (or scan a flat collection) — otherwise the interactive folder-picker prompt will hang the job the same way.
- Store `OPENROUTER_API_KEY` and any `auth-file` credentials as encrypted CI secrets, never in the repo.
- Commit a `--cache` file to the repo (or restore it from a CI cache action) so PR runs reuse prior AI decisions instead of re-synthesizing probes on every push — faster and cheaper.
- Use `if: always()` on the report-upload step so you get the partial report even when the scan fails or aborts on an infrastructure error (exit code 3).
- Treat exit code `3` differently from `1` in your pipeline logic if you want infra flakiness (AI backend down) to retry rather than fail the build outright.

#### Complete, hardened manifest example

The minimal example above is enough to get running, but two classes of failure show up almost immediately in practice: the collection/auth-file path doesn't actually exist in the checked-out repo (wrong path, wrong case, or gitignored secrets file never reaching the runner), and the tool version drifts silently because `main` is cloned fresh on every run. This version fixes both, plus persists the AI decision cache properly instead of writing it into a directory that gets discarded at job end:

```yaml
# .github/workflows/api-security.yml
name: API Security Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  apinspect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      # Pin to a released tag/commit, not a moving `main` — a breaking change
      # in APInspect itself should never silently change your gate's behavior
      # with no diff in this repo to review.
      - name: Install APInspect
        run: |
          git clone --branch v1.0.0 https://github.com/HovSaintBrandon/APInspect.git apinspect-tool
          cd apinspect-tool && npm ci

      # Materialize the auth file from secrets — it's gitignored on purpose
      # (see "Input Files You Need to Prepare"), so it never reaches the
      # runner via actions/checkout and must be reconstructed here.
      - name: Write auth file from secrets
        run: |
          mkdir -p ci
          cat <<'EOF' > ci/apinspect_auth.json
          {
            "roles": [
              {
                "name": "student",
                "auth_type": "bearer",
                "login_endpoint": "${{ secrets.LOGIN_ENDPOINT }}",
                "method": "POST",
                "token_path": "data.access_token",
                "payload": { "email": "${{ secrets.STUDENT_EMAIL }}", "password": "${{ secrets.STUDENT_PASSWORD }}" }
              }
            ]
          }
          EOF

      # Fail fast with a clear message instead of letting APInspect's
      # generic parser error be the first sign something's wrong.
      - name: Verify required files exist
        run: |
          test -f collections/VenuefyProd.json || { echo "::error::Missing collections/VenuefyProd.json in $(pwd)"; find . -maxdepth 3 -iname "*.json" | grep -v node_modules; exit 1; }
          test -f ci/apinspect_auth.json || { echo "::error::Auth file still missing after materialization"; exit 1; }
          mkdir -p reports

      # Persist AI applicability/probe decisions across runs — restored
      # before the scan, saved after, keyed on the collection's content so
      # a changed collection invalidates stale entries automatically.
      - uses: actions/cache@v4
        with:
          path: apinspect-tool/.apinspect-cache.json
          key: apinspect-cache-${{ hashFiles('collections/VenuefyProd.json') }}

      - name: Run security scan
        env:
          OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
        run: |
          node apinspect-tool/src/cli/index.js scan collections/VenuefyProd.json \
            --checklist \
            --style rest \
            --base-url ${{ secrets.STAGING_API_URL }} \
            --auth-file ci/apinspect_auth.json \
            --cache apinspect-tool/.apinspect-cache.json \
            --fail-on high \
            -o reports/scan.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: apinspect-report
          path: reports/
```

Repo secrets to configure once (**Settings → Secrets and variables → Actions**): `OPENROUTER_API_KEY`, `STAGING_API_URL`, `LOGIN_ENDPOINT`, `STUDENT_EMAIL`, `STUDENT_PASSWORD` (add one email/password pair per role in your auth file).

### GitLab CI

```yaml
api_security_scan:
  stage: test
  image: node:20
  script:
    - git clone <apinspect-repo-url> apinspect-tool
    - cd apinspect-tool && npm ci
    - node src/cli/index.js scan ../collections/api.postman_collection.json
        --checklist --style rest
        --base-url "$STAGING_API_URL"
        --auth-file ../ci/apinspect_auth.json
        --fail-on high
        -o ../reports/scan.json
  artifacts:
    when: always
    paths:
      - reports/
  variables:
    OPENROUTER_API_KEY: $OPENROUTER_API_KEY   # set as a masked CI/CD variable
```

### Generic (Jenkins, CircleCI, etc.)

The contract is the same everywhere: install Node, `npm ci`, set `OPENROUTER_API_KEY`, run `scan --checklist --style ... --fail-on ...`, check the exit code, archive `reports/`. Any pipeline that can run a shell step can gate on this.

---

## Exit Codes

This table covers `scan <file>` (the AI-checklist and legacy hardcoded paths). Declarative mode
(`scan --config`) has its own, narrower exit-code contract — see
[docs/APINSPECT-DECLARATIVE-MODE.md](docs/APINSPECT-DECLARATIVE-MODE.md#exit-codes).

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding met the `--fail-on` threshold (or `--fail-on` wasn't set) |
| `1` | A confirmed finding (or, with `--fail-on-tbc`, a `TO BE CONFIRMED` finding) met or exceeded the `--fail-on` severity — or a non-infrastructure runtime error occurred |
| `2` | Invalid CLI arguments (bad `--fail-on`/`--style` value, or `--fail-on-tbc` used without `--fail-on`) |
| `3` | Infrastructure failure — e.g. the AI backend was unreachable or returned a billing/auth error mid-scan, or the preflight check found every REST endpoint in the collection returning 404 (almost always a wrong `--base-url` or an unresolved path template). Partial results are still written to a `.partial.json` file, but **must not be used for gating** — treat as inconclusive, not passing. |

On a code-`3` abort the console also prints a summary of whatever was recorded before the abort (pass/fail/warn counts, plus every FAIL/WARN/TO BE CONFIRMED finding so far) and which endpoint was in flight when it died — no need to open the `.partial.json` file just to see what happened. A full forensic record (timestamp, the exact error incl. stack trace, sanitized CLI args, endpoint in flight, role) is also appended as one JSON line to `reports/abortlogs.jsonl` — append-only, so a history of aborts across runs survives instead of each one overwriting the last.

---

## Reports

| Format | Flag | Use case |
|---|---|---|
| JSON | default, or `-o report.json` | Machine-readable; feed into other tooling |
| CSV | `-o report.csv` | Spreadsheet-friendly flat export |
| FALCON review | `-o report.falcon.csv` | Purpose-built triage spreadsheet — grouped by severity/category for manual review sign-off |

Each result includes `check`, `endpoint`, `method`, `status`, `severity`, `confirmation_status`, `message`, a full `evidence_trail` (request/response pair, whenever a request was actually sent — hardcoded checks and AI-driven ones alike) for auditability, and — for AI-driven checks specifically — `ai_confidence`, `ai_reasoning`, `evidence_cited`.

`status` is one of: `PASS`, `FAIL`, `N/A` (genuinely not applicable to this endpoint/protocol), `MANUAL` / `TO BE CONFIRMED` (a real evaluation was attempted but needs human judgment), or a coverage-gap status — `AUTH_BLOCKED` (request was stopped by a 401/403 before the check under test could run), `ROUTE_NOT_FOUND` (404 — no route matched, so nothing about the endpoint could be evaluated), `ENDPOINT_UNHEALTHY` (a baseline request 5xx'd, so dependent checks were skipped as unreliable), or `UNRESOLVED_PATH` (the spec's path template never resolved to a real URL, so no request was sent at all). Coverage-gap statuses are never folded into `PASS`/`N/A` — the JSON report's `summary` block breaks them out individually plus a `coverage.coverage_pct` (evaluated ÷ applicable), so a high pass count can't quietly hide low real coverage.

When scanning with a multi-role `--auth-file`, per-role reports are written automatically (e.g. `report.student.json`, `report.admin.json`) alongside the combined run.

---

## Project Layout

```
src/
  cli/
    index.js                 CLI entry point (commander) — scan / audit / analyze / headers / check / jwt
    authResolver.js          Shared auth-file/token/basic-auth resolution (scan + headers + check)
  core/
    parser.js                Input detection + normalization (Postman/OpenAPI/GraphQL/gRPC)
    engine.js                Main scan loop — checklist mode + legacy mode
    context.js                Per-scan state: auth, endpoints, variable store, results
    discovery.js              Pre-scan reachability + variable harvesting
    headerGrader.js           securityheaders.com-style header scoring engine (no network)
    openrouterClient.js      AI backend HTTP client (retries, error classification)
    ai/
      applicabilityEngine.js  Which checklist items apply to this endpoint
      probeSynthesizer.js     Builds a context-aware attack request
      verdictClassifier.js    Judges the response, assigns confidence
    jwt/
      jwtCodec.js              Base64url decode/encode — raw JWT parsing, no verification
      jwtStaticAnalysis.js     Header (alg/kid/jku/jwk) + claims (exp/aud/iss/jti) findings
      jwtForge.js              Builds forged tokens: alg=none, alg confusion, secret cracking, kid injection
      jwtLiveTester.js         Fires forged tokens at a live endpoint, classifies accepted/rejected/inconclusive
  adapters/
    rest/, graphql/, grpc/    Protocol-specific transport + discovery
  checks/                     Hardcoded, deterministic check modules
  reporters/                  json / csv / FALCON reporters
  config/
    checklist.json            The 34-item security checklist
    securityHeaderRules.json   Header grading rule set — weights, quality checks, recommendations
    commonJwtSecrets.json      Built-in weak-secret wordlist for `apinspect jwt` HMAC cracking
    aiConfig.js                Model + confidence threshold configuration
eval/
  run.js                      Eval harness against a mock server + ground truth
```

---

## Troubleshooting

- **`Infrastructure failure: OpenRouter API call failed: Request failed with status code 402`** — your OpenRouter account is out of credits/quota. Top up or check billing at `openrouter.ai/credits`; not a code bug.
- **Scan hangs with no output** — you're likely running an ambiguous input (Postman/OpenAPI/JSON) without `--style` in a non-interactive shell (CI), or a Postman collection with folders without `--folder`. Pass `--style rest|graphql|grpc` and, if applicable, `--folder <name>` explicitly.
- **`AUTH-01` and `AUTH-02`/`AUTH-03` disagree** — if you're on an older build, upgrade: a fixed version now reads the actual no-auth response status instead of assuming public access. Confirm the fix is present in `src/checks/authentication/authRequired.js`.
- **`DATA-02` / other checks stuck on `MANUAL`: "No captured response available"** — run `apinspect audit <file>` first to populate the evidence store, then re-run `scan --checklist`.

---

<div align="center">
  <sub>Built by HovSaintBrandon</sub>
</div>
