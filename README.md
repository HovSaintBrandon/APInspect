<div align="center">

# 🛡️ APInspect
### Automated API Security Checklist & Scanner

[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![Node.js](https://img.shields.io/badge/Node.js-v14+-green.svg)](https://nodejs.org/)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)

**A checklist-driven security scanner designed to automate the reconnaissance and vulnerability assessment of REST APIs.**

</div>

---

## 📖 What is APInspect?

**APInspect** is a specialized security tool built to automate the tedious parts of API security testing. Unlike generic scanners, it follows a structured **Checklist Methodology**, verifying specific security controls endpoint-by-endpoint.

It is designed for developers and security engineers to:
1.  **Parse** API definitions (Postman Collections or JSON configs).
2.  **Audit** endpoints using active probing and static analysis.
3.  **Report** actionable findings in JSON or CSV formats.

---

## ⚙️ How It Works

APInspect operates by ingesting an API definition file. It maps out the attack surface (endpoints + methods) and runs a suite of pluggable **Check Modules** against each one.

1.  **Initialization**: Parses the input file (`.json`) and applies global configurations (Auth tokens, base URLs).
2.  **Engine Execution**: The core engine iterates through every endpoint.
3.  **Active Probing**: For each endpoint, it performs safe but effective checks:
    *   *Fuzzing parameters* for Injection vulnerabilities.
    *   *Stripping authentication* to test access controls.
    *   *Flooding requests* to verify rate limiting.
    *   *Analyzing headers* for misconfigurations.
4.  **Reporting**: Aggregates all Pass/Fail/Warn results into a clean report.

---

## 🚀 Installation & Usage

### Prerequisites
*   Node.js v14+
*   NPM

### Installation
```bash
git clone https://github.com/your-repo/APIscanner.git
cd APIscanner
npm install
npm link # Optional: to expose 'apinspect' globally
```

### 🎮 Commands

#### 1. active Scan (Primary)
Performs a full active security scan against an API definition.

```bash
apinspect scan <file.json> [options]
```
**Options:**
*   `-t, --token <token>`: Bearer token for authentication.
*   `-u, --username <user>`: Username for Basic Auth.
*   `-p, --password <pass>`: Password for Basic Auth.
*   `-o, --output <path>`: Path to save the report (supports `.json` or `.csv`).

**Example:**
```bash
apinspect scan ./my-api-collection.json -t eyJhbGci... -o ./reports/audit.csv
```

#### 2. Static Analysis
Analyzes a Postman collection structure for potential issues without making requests.

```bash
apinspect analyze <collection.json>
```

#### 3. Newman Audit
Runs the collection using Newman (standard Postman runner) and audits the responses for leaks.

```bash
apinspect audit <collection.json> -e <environment.json>
```

---

## 🔍 Security Checks & Test Subjects

APInspect performs a rigorous set of checks categorized by vulnerability type.

### 🕵️ Discovery & Recon
*   **Identify API Endpoints**: Verifies that documented endpoints are reachable and determines their status code.
*   **Enumerate HTTP Methods**: Checks for `OPTIONS` headers (`Allow`) and specifically scans for dangerous methods like `TRACE` (Cross-Site Tracing risk).

### 🔐 Authentication
*   **Auth Enforcement**: actively strips authentication headers (`Authorization`, tokens) from requests to ensure the API correctly responds with `401 Unauthorized` or `403 Forbidden` instead of leaking data.

### 💉 Injection Attacks
*   **SQLi & XSS Fuzzing**: Injects common payloads (e.g., `'`, `"`, `<script>`, `OR 1=1`) into GET parameters to detect unhandled server errors (500s) indicating potential vulnerabilities.
*   **Path Traversal**: Fuzzes URL parameters with dot-dot-slash patterns (`../../etc/passwd`, `..\windows\win.ini`) to check for file system leakage.

### 👁️ Data Exposure
*   **Sensitive Data Leaks**: Scans response bodies using regex patterns to detect:
    *   [x] Email Addresses
    *   [x] US Social Security Numbers (SSN)
    *   [x] Private Keys (RSA/DSA)
    *   [x] AWS Access Keys
    *   [x] JWT Tokens
    *   [x] Stripe & Google API Keys

### 🔧 Misconfigurations
*   **CORS Policy**: Checks for insecure Cross-Origin Resource Sharing configurations:
    *   `Access-Control-Allow-Origin: *` (Wildcard/Public access).
    *   Reflected Origins combined with `Access-Control-Allow-Credentials: true`.
*   **Security Headers**: Audits for missing or insecure headers:
    *   **Missing**: `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`.
    *   **Leaking**: `X-Powered-By`, `Server` (version disclosure).

### 💥 Error Handling
*   **Stack Trace Exposure**: Intentionally sends malformed JSON or bad requests to trigger application errors, then scans the response for stack traces, runtime error names (`SyntaxError`, `ReferenceError`), or internal path information.

### 🚦 Rate Limiting
*   **Brute Force Protection**: Sends a parallel burst of requests (default: 10) to an endpoint to verify if the server responds with `429 Too Many Requests`.

---

<div align="center">
  <sub>Built with ❤️ by HovSaintBrandon </sub>
</div>
