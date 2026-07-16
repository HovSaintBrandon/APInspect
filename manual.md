# APInspect Manual

APInspect is a Checklist-driven API security scanner designed to automate the reconnaissance and vulnerability assessment of REST APIs. Unlike generic scanners, it validates specific security controls endpoint-by-endpoint following a structured methodology.

This manual explains how the tool works, its core components, its AI-driven checklist engine, and how to configure and run it effectively.

---

## Core Architecture

APInspect functions in two main scanning modes:

1. **Legacy Mode**: Runs a flat list of hardcoded security checks (e.g., fuzzing, injection) against the discovered endpoints.
2. **Checklist Mode (AI-Driven)**: Runs a comprehensive checklist (defined in `src/config/checklist.json`). For each endpoint, it uses AI to determine if a check is applicable, synthesize specific probes, and classify the response verdict.

Regardless of the mode, the execution flow is generally the same:
1. **Parser Phase**: Ingests an API definition file (e.g., Postman Collection, OpenAPI config) and extracts the attack surface (endpoints and methods).
2. **Discovery Phase**: Sends initial discovery requests to see which endpoints are reachable and what methods are actually allowed.
3. **Execution Engine Phase**: Runs the configured checks against every endpoint.
4. **Reporting Phase**: Outputs the scan results in JSON or CSV formats.

---

## Operating Modes

APInspect provides three main CLI commands:

### 1. Scan (`apinspect scan <file>`)
The primary active security scanning module. It maps out the attack surface and tests each endpoint against vulnerabilities.

**Example Usage**:
```bash
apinspect scan ./my-api.json -t "my-bearer-token" -b "https://api.example.com"
```

**Key Options**:
- `-b, --base-url <url>`: Override the base URL.
- `-t, --token <token>`: Provide a Bearer token for auth.
- `-u, --username <user>` / `-p, --password <pass>`: Provide Basic Auth credentials.
- `--auth-file <path>`: Advanced dynamic multi-role authentication (see Authentication Section).
- `--checklist`: Enable the AI-driven checklist mode.
- `-o, --output <path>`: Output file path (supports `.json`, `.csv`, `.falcon.csv`).

### 2. Audit (`apinspect audit <file>`)
Runs a Postman collection via the standard Newman runner and subsequently analyzes the responses for security issues, such as sensitive data leakage.

**Example Usage**:
```bash
apinspect audit ./my-collection.json -e ./my-env.json
```

### 3. Analyze (`apinspect analyze <file>`)
A static analysis tool that analyzes an API structure (e.g. Postman JSON) without making any active HTTP requests. It looks for potential structural and definitional misconfigurations.

**Example Usage**:
```bash
apinspect analyze ./my-collection.json
```

---

## The AI-Driven Checklist Engine (`--checklist` flag)

When the `--checklist` flag is passed to the `scan` command, APInspect loads an expanded set of security requirements from `src/config/checklist.json` (such as Business Logic flaws, WebSockets, Mass Assignment, and more).

The AI pipeline acts in three stages during the scan of an endpoint:

1. **Applicability Engine (`applicabilityEngine.js`)**: Evaluates the endpoint context against the `checklist.json` to filter out non-applicable checks. To minimize latency and cost, this is **batched per endpoint**—a single LLM call evaluates the endpoint against the entire checklist simultaneously. The result is then cached in-memory by endpoint signature (`METHOD /path`), ensuring each endpoint is only processed once per run.
2. **Probe Synthesizer (`probeSynthesizer.js`)**: For checklist items requiring active testing, the AI synthesizes an intelligent, context-aware HTTP request tailored specifically for the vulnerability being tested. Note that probe generation operates with a non-zero temperature (`0.1`), meaning **probes can slightly drift between runs** on the same target. This provides fuzzing-like variance but means runs are not strictly deterministic.
3. **Verdict Classifier (`verdictClassifier.js`)**: Evaluates the HTTP response from the synthesized probe. The AI assigns a status (`PASS`, `FAIL`, `N/A`, `TO BE CONFIRMED`) and a confidence score. If the AI's confidence falls below defined thresholds (e.g. `AI_FAIL_CONFIDENCE_THRESHOLD`), the tool will gracefully downgrade the verdict to `TO BE CONFIRMED` to prevent false positives.

For checks in the checklist that can be covered by hardcoded scripts (e.g., standard SQLi fuzzing), the engine routes them back to the traditional deterministic modules (e.g. `injection/sqliXss`).

---

## Authentication Configuration

APInspect supports three main ways to authenticate:

### 1. Command Line Arguments
Useful for quick scans.
- **Bearer Token**: `apinspect scan file.json -t <token>`
- **Basic Auth**: `apinspect scan file.json -u admin -p pass123`

### 2. Multi-Role Dynamic Authentication (`--auth-file`)
When using `--auth-file`, APInspect can scan the API from the perspective of multiple user roles, checking authorization and access controls automatically.

The Auth configuration JSON supports dynamically fetching tokens before the scan starts:
```json
{
  "roles": [
    {
      "name": "admin",
      "auth_type": "bearer",
      "login_endpoint": "https://api.example.com/v1/login",
      "method": "POST",
      "payload": { "email": "admin@example.com", "password": "secure" },
      "token_path": "data.jwt_token"
    },
    {
      "name": "guest",
      "auth_type": "basic",
      "credentials": { "username": "guest", "password": "password" }
    }
  ]
}
```

APInspect will then run an isolated scan for **each role** and generate separate reports.

---

## Security Checks Provided

APInspect is designed to cover key OWASP Top 10 vulnerabilities:

1. **Discovery & Recon**: Endpoint reachability and dangerous HTTP methods (`TRACE`, `CONNECT`).
2. **Authentication**: Missing auth enforcement (`401/403` validation), Broken Object-Level Authorization (BOLA).
3. **Injection**: Parameter fuzzing for SQLi, XSS, SSRF, and Path Traversal (`../../`).
4. **Data Exposure**: Static regex tracking of sensitive data (Emails, SSNs, API Keys, JWTs) + AI detection of subtle exposure.
5. **Misconfigurations**: Insecure CORS policies (Wildcard `*` + credentials), Missing Security Headers (HSTS, CSP).
6. **Error Handling**: Causing `500 Internal Server Error`s to extract Stack Traces and backend paths.
7. **Rate Limiting**: Verifies `429 Too Many Requests` behavior by emitting parallel bursts of requests. The burst logic relies on a **first-party unthrottled Promise flood** (via `Promise.all` in `bruteForce.js`), rather than utilizing strict HTTP client concurrency controls, aggressively testing the server's immediate rejection limits.
8. **Business Logic & Mass Assignment** (Checklist Mode): Contextual boundary manipulation, unexpected object fields, and workflow skipping.

---

## Output Formats

APInspect allows exporting findings into formats suitable for automation and reporting:
- **JSON**: The default rich output format.
- **CSV**: Standard comma-separated format.
- **Falcon CSV (`.falcon.csv`)**: A specialised CSV layout matching spreadsheet templates used for security review and sign-off workflows. When multi-role scanning is enabled, files will be suffixed by role (e.g., `report.admin.falcon.csv`).
