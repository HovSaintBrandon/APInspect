# Declarative CLI mode — the CI-safe scan path

`apinspect scan --config apinspect.config.yaml` is a second way to run a scan, alongside the
existing `apinspect scan <file> [--checklist]`. **Neither replaces the other** — they coexist on
the same `scan` command (mutually exclusive: pass a positional file *or* `--config`, never both),
and picking one has no effect on the other.

## Why a second mode

The existing AI-driven `--checklist` path is genuinely useful — it discovers applicable checks,
synthesizes probes, and classifies verdicts with an LLM. But that also makes it non-reproducible
(the model decides what to look at, and can differ run to run) and dependent on a third-party AI
backend that can fail for reasons that have nothing to do with the target API — an OpenRouter
account running out of credits, a model getting deprecated, a provider being rate-limited. Several
of those exact failures got investigated and hardened earlier in this tool's development; none of
that hardening changes the fact that a CI gate should not depend on a third-party LLM being up.

Declarative mode has **zero LLM calls in its entire path**. Every check that runs, every endpoint
it runs against, and every host it's allowed to touch is fixed by `apinspect.config.yaml` before
the scan starts. Same config, same target, same findings, every time — which is what "safe to gate
a build on" actually requires.

## Config format

See [`apinspect.config.example.yaml`](../apinspect.config.example.yaml) at the repo root for a
complete, commented example. Key fields:

| Field | Required | Notes |
|---|---|---|
| `version` | Yes | Must be `1`. |
| `target.base_url` | Yes | The API's base URL. |
| `target.allowlist` | Yes, non-empty | Every host a request (including a redirect target) may reach — see [Allowlist enforcement](#allowlist-enforcement). |
| `auth` | No | Omit to scan unauthenticated. `type: keycloak` + `token_env: <ENV_VAR_NAME>` reads a pre-provisioned bearer token from the environment — no live login call. |
| `endpoints[].path` / `.methods` / `.checks` | Yes | Each method in `.methods` gets every check in `.checks` run against it. |
| `endpoints[].body` | No | Request body for a body-carrying method (POST/PUT/PATCH). |
| `gate.fail_on` | No (default `high`) | `none \| low \| medium \| high \| critical` — `none` never fails the build regardless of findings. |
| `gate.fail_on_partial` | No (default `true`) | `true`: an aborted run exits 3 (build fails). `false`: exits 0 despite the abort — coverage silently drops, use with care. |
| `gate.max_new_findings` | No (default off) | This pass: compared against the **total** FAIL count — there's no run-to-run diffing yet (planned for the MCP server's `diff_runs` tool), so "new" and "total" are the same thing today. |
| `redact_fields` | No | Extra header/body field names (case-insensitive), beyond the built-in `authorization`/`cookie`/`x-api-key`, to redact from evidence in the written artifacts. |
| `output.dir` / `.formats` | No (defaults shown in the example) | Where runs are written and which formats (`json`, `sarif`) to emit. |

## Checks

A separate, smaller ID scheme from the AI-driven path's `checklist.json` (DISC-01, AUTH-01, ...) —
these are deterministic, OWASP API Security Top 10-labeled, and live at `src/core/checks/`:

| Check ID | Covers | Implementation |
|---|---|---|
| `API1_BOLA` | Broken Object Level Authorization | **Not implemented** — see below |
| `API2_BROKEN_AUTH` | Broken Authentication | Wraps the existing `authentication/authRequired` check |
| `API3_BOPLA` | Broken Object Property Level Authorization (mass assignment) | New — injects privileged extra fields, checks for reflection |
| `API4_RATE_LIMIT` | Unrestricted Resource Consumption | Wraps the existing `rateLimiting/bruteForce` check |
| `API5_BFLA` | Broken Function Level Authorization | **Not implemented** — see below |
| `API8_MISCONFIG` | Security Misconfiguration | Combines the existing CORS + security-header checks |
| `API8_2019_INJECTION` | SQLi/XSS/path traversal | Combines the existing injection checks — labeled against the *2019* OWASP API Top 10, since the 2023 edition dropped a dedicated numbered Injection category and there's no correct 2023 ID to claim here |

**`API1_BOLA` and `API5_BFLA` return a `NOT_IMPLEMENTED` result, not a false PASS.** Both need a
*second* authenticated identity to test properly — does identity A's token reach an object identity
B owns (BOLA), or a function identity B shouldn't be able to call (BFLA)? Today's `auth:` block is
a single identity, and inventing a multi-identity config format wasn't part of this pass. A scan's
`findings.json`/coverage will show these as `NOT_IMPLEMENTED`, distinct from every other status, so
it can't be misread as "tested and clean." Testing these two categories still needs to happen
manually until that config format exists.

## Allowlist enforcement

`src/core/allowlist.js` is the only place a host gets authorized, and it reads exclusively from the
already-loaded config — no CLI flag or (future) MCP tool argument can add a host at runtime. It's
enforced twice: once before the first request (`target.base_url` itself must be in
`target.allowlist`, checked at startup — a mismatch is a config error, exit 2, before any request is
sent), and again on **every redirect hop** via axios's `beforeRedirect` hook, so a target that
redirects off-allowlist gets the redirect rejected, not silently followed.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed, nothing at or above `gate.fail_on` |
| `1` | Completed, findings at or above `gate.fail_on`, or `gate.max_new_findings` exceeded |
| `2` | Config invalid, an unknown check ID was referenced, or `target.base_url`'s host isn't in `target.allowlist` |
| `3` | Run aborted before completing every endpoint (network/timeout against the target — this path makes no LLM calls, so this is never an AI backend failure). Only exits 3 if `gate.fail_on_partial` is `true`; otherwise exits `0`. |
| `4` | `auth.token_env` is set in config but the named environment variable isn't set |

## Artifacts

Each run writes to `<output.dir>/<timestamp>/` (default `.apinspect/runs/<timestamp>/`), plus a
`latest/` copy (a real copy, not a symlink — symlinks don't reliably survive a CI artifact
upload/download round trip):

- **`findings.json`** — every check result, redacted (see below).
- **`findings.sarif`** — SARIF 2.1.0, `FAIL`-status findings only, for code-scanning upload (e.g.
  GitLab's `reports.sast`, GitHub code scanning).
- **`manifest.json`** — `config_hash` (sha256 of the raw config file — two runs are only comparable
  when this matches), `target`, `completed`, `abort_reason`, and finding counts.

**Redaction happens once, in `src/core/artifacts.js`, on the way to disk** — `Authorization`,
`Cookie`, and `X-Api-Key` headers (case-insensitive) are always redacted, and so are
`token`/`access_token`/`refresh_token`/`id_token`/`password`/`secret`/`api_key`/`authorization`
body fields in both the request *and* the response (a target echoing a caller-supplied token back
in its response body is common enough that this is on by default, not opt-in). Anything named in
`redact_fields` is redacted the same way, on top of those defaults. This is the only place in the
declarative path that writes scan output — and the MCP server's `run_check` tool reuses this exact
function for its live results too — so it's the one place that has to get this right.

## GitLab CI

```yaml
api-security:
  stage: test
  script:
    - apinspect scan --config apinspect.config.yaml
  artifacts:
    when: always
    paths:
      - .apinspect/runs/
    reports:
      sast: .apinspect/runs/latest/findings.sarif
  variables:
    APINSPECT_TOKEN: $KEYCLOAK_SCAN_TOKEN
```

## What's not in this pass

- **The MCP server** is now built — see [docs/APINSPECT-MCP-SERVER.md](APINSPECT-MCP-SERVER.md).
- **`diff_runs`'s baseline strategy isn't automated yet** — planned: the last completed run on
  `main` with a matching `config_hash`, everything `manifest.json` already records to make that
  lookup possible.
- **BOLA/BFLA** — see [Checks](#checks) above.
