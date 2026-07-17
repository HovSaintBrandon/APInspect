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
   - Items requiring judgment (`requires_ai_probe`) go through the **Probe Synthesizer** (builds a context-aware HTTP request) and then the **Verdict Classifier** (judges the response, cites evidence, assigns confidence).
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
| Misconfigurations | CORS wildcard/reflected-origin, missing security headers, version disclosure |
| Error Handling | Stack traces, verbose framework errors |
| Rate Limiting | Brute-force burst testing, header-spoofing bypass attempts |
| Mass Assignment | Privileged-field injection (`role`, `isAdmin`, `ownerId`) |
| Business Logic | Workflow-step skipping, transaction/quantity limits, out-of-range values |
| Third-Party Integration | Callback/webhook URL validation |
| CI/CD & Infrastructure | Leaked credentials, exposed debug/staging endpoints |
| GraphQL Security | Introspection exposure, query-depth DoS |
| gRPC Security | Metadata auth stripping, TLS enforcement, reflection, message-size limits |
| WebSocket Security | Auth on upgrade, message-level authorization |

---

## Installation

### Prerequisites
- Node.js v14+
- npm
- A [Cerebras Cloud](https://cloud.cerebras.ai) API key (only required for `--checklist` mode — the AI-driven pipeline)

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

Checklist mode needs a Cerebras API key. Copy the example env file and fill it in:

```bash
cp .env.example .env
```

```env
# .env
CEREBRAS_API_KEY=your_key_here
```

`.env` is gitignored — never commit real keys. In CI, inject this as a secret environment variable instead (see [CI/CD](#embedding-in-a-cicd-pipeline)).

Model and confidence thresholds are tunable in `src/config/aiConfig.js` — don't hardcode the model ID anywhere else.

---

## Input Files You Need to Prepare

Everything else in this tool — discovery, style resolution, the checklist run, per-role comparisons — is derived from two files you provide. Neither is generated for you; you bring them from your own API project.

### 1. The API definition file (required)

This is what `parser.js` reads to build the attack surface (`config.endpoints`, `config.base_url`, `config.protocol`). Bring **whichever of these you already have** — you don't need to write a new format:

| You already have... | Give APInspect... | What happens |
|---|---|---|
| A Postman collection you export from Postman | the `.json` export, unmodified | `extractPostmanEndpoints` walks every `item`/folder and flattens it to `{ path, methods }`. You'll be asked (or pass `--style`) to confirm REST vs. GraphQL, since a Postman file alone doesn't say which. |
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
| `--auth-file <path>` | Multi-role auth config — see [Authentication](#authentication) |
| `--checklist` | Enable AI-driven checklist mode (recommended — otherwise a smaller hardcoded legacy check list runs) |
| `--cache <path>` | Persist AI applicability/probe decisions to a file — reused on the next run against an unchanged target, and committable for deterministic CI runs |
| `-o, --output <path>` | Report path — `.json`, `.csv`, or `.falcon.csv` (review spreadsheet format) |
| `--fail-on <severity>` | Exit code 1 if any confirmed finding meets/exceeds this severity: `critical`, `high`, `medium`, `low`, `info` |
| `--fail-on-tbc` | Also count `TO BE CONFIRMED` findings toward `--fail-on` (requires `--fail-on`) |

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
          CEREBRAS_API_KEY: ${{ secrets.CEREBRAS_API_KEY }}
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

Key points for CI:
- Always pass `--style` explicitly in CI — with no TTY attached, the interactive style prompt for ambiguous inputs (Postman/OpenAPI/raw JSON) will hang the job waiting for input it will never receive.
- Store `CEREBRAS_API_KEY` and any `auth-file` credentials as encrypted CI secrets, never in the repo.
- Commit a `--cache` file to the repo (or restore it from a CI cache action) so PR runs reuse prior AI decisions instead of re-synthesizing probes on every push — faster and cheaper.
- Use `if: always()` on the report-upload step so you get the partial report even when the scan fails or aborts on an infrastructure error (exit code 3).
- Treat exit code `3` differently from `1` in your pipeline logic if you want infra flakiness (AI backend down) to retry rather than fail the build outright.

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
    CEREBRAS_API_KEY: $CEREBRAS_API_KEY   # set as a masked CI/CD variable
```

### Generic (Jenkins, CircleCI, etc.)

The contract is the same everywhere: install Node, `npm ci`, set `CEREBRAS_API_KEY`, run `scan --checklist --style ... --fail-on ...`, check the exit code, archive `reports/`. Any pipeline that can run a shell step can gate on this.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding met the `--fail-on` threshold (or `--fail-on` wasn't set) |
| `1` | A confirmed finding (or, with `--fail-on-tbc`, a `TO BE CONFIRMED` finding) met or exceeded the `--fail-on` severity — or a non-infrastructure runtime error occurred |
| `2` | Invalid CLI arguments (bad `--fail-on`/`--style` value, or `--fail-on-tbc` used without `--fail-on`) |
| `3` | Infrastructure failure — e.g. the AI backend was unreachable or returned a billing/auth error mid-scan. Partial results are still written to a `.partial.json` file, but **must not be used for gating** — treat as inconclusive, not passing. |

---

## Reports

| Format | Flag | Use case |
|---|---|---|
| JSON | default, or `-o report.json` | Machine-readable; feed into other tooling |
| CSV | `-o report.csv` | Spreadsheet-friendly flat export |
| FALCON review | `-o report.falcon.csv` | Purpose-built triage spreadsheet — grouped by severity/category for manual review sign-off |

Each result includes `check`, `endpoint`, `method`, `status`, `severity`, `confirmation_status`, `message`, and — for AI-driven checks — `ai_confidence`, `ai_reasoning`, `evidence_cited`, and a full `evidence_trail` (request/response pair) for auditability.

When scanning with a multi-role `--auth-file`, per-role reports are written automatically (e.g. `report.student.json`, `report.admin.json`) alongside the combined run.

---

## Project Layout

```
src/
  cli/index.js              CLI entry point (commander) — scan / audit / analyze
  core/
    parser.js                Input detection + normalization (Postman/OpenAPI/GraphQL/gRPC)
    engine.js                Main scan loop — checklist mode + legacy mode
    context.js                Per-scan state: auth, endpoints, variable store, results
    discovery.js              Pre-scan reachability + variable harvesting
    cerebrasClient.js         AI backend HTTP client (retries, error classification)
    ai/
      applicabilityEngine.js  Which checklist items apply to this endpoint
      probeSynthesizer.js     Builds a context-aware attack request
      verdictClassifier.js    Judges the response, assigns confidence
  adapters/
    rest/, graphql/, grpc/    Protocol-specific transport + discovery
  checks/                     Hardcoded, deterministic check modules
  reporters/                  json / csv / FALCON reporters
  config/
    checklist.json            The 34-item security checklist
    aiConfig.js                Model + confidence threshold configuration
eval/
  run.js                      Eval harness against a mock server + ground truth
```

---

## Troubleshooting

- **`Infrastructure failure: Cerebras API call failed: Request failed with status code 402`** — your Cerebras account is out of credits/quota. Top up or check billing at `cloud.cerebras.ai`; not a code bug.
- **Scan hangs with no output** — you're likely running an ambiguous input (Postman/OpenAPI/JSON) without `--style` in a non-interactive shell (CI). Pass `--style rest|graphql|grpc` explicitly.
- **`AUTH-01` and `AUTH-02`/`AUTH-03` disagree** — if you're on an older build, upgrade: a fixed version now reads the actual no-auth response status instead of assuming public access. Confirm the fix is present in `src/checks/authentication/authRequired.js`.
- **`DATA-02` / other checks stuck on `MANUAL`: "No captured response available"** — run `apinspect audit <file>` first to populate the evidence store, then re-run `scan --checklist`.

---

<div align="center">
  <sub>Built by HovSaintBrandon</sub>
</div>
