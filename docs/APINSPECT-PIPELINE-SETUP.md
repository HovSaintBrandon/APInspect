# APInspect in CI/CD — What Devs Need to Prepare, What Goes in Git, and Why

## The two files every scan needs

APInspect never generates its own inputs — every scan is driven by two files a dev brings from their own project:

| File | What it is | Required? |
|---|---|---|
| **API definition** (Postman collection / OpenAPI spec / GraphQL SDL / `.proto`) | Tells APInspect *what to hit* — the endpoints, methods, and request shapes. | Yes, always |
| **Auth file** (`apinspect_auth.json` or similar) | Tells APInspect *how to log in* as one or more roles before running the checklist against each endpoint. | No — but without it, every check that needs a real session (BOLA, mass assignment, data exposure post-auth) comes back `MANUAL`/`TO BE CONFIRMED` instead of a real `PASS`/`FAIL`. If you want the scan to actually mean something, bring one. |

## What should be committed vs. not

| File | Commit to git? | Why |
|---|---|---|
| API definition (Postman/OpenAPI/etc.) | ✅ Yes | It's just endpoint shape — no secrets in a well-formed export. This *should* live in the repo so the scan is reproducible and reviewable in a PR diff. |
| Auth file **template** (`apinspect_auth.template.json`, with placeholders like `"password": "$STUDENT_PASSWORD"`) | ✅ Yes | Shows the shape of the real file without containing a real credential. |
| Auth file with **real credentials filled in** | ❌ Never | This is a live username/password or login payload for a test account. Committing it puts a working credential in git history forever — even if you delete it in a later commit, it's still retrievable from history. |
| `.env` / `CEREBRAS_API_KEY` | ❌ Never | It's a billing-linked API key. Anyone with repo read access (or anyone who forks/clones before you rotate it) can run up usage on your account. |
| `--cache` file (`.apinspect-cache.json`) | ✅ Optional, recommended | Contains AI *decisions* (which checks applied, what probe was built), not credentials or secrets — safe to commit, and doing so makes AI verdicts reproducible run-to-run instead of drifting slightly each time. |
| `reports/` output | Usually ❌ (gitignored by default) | Reports can contain **evidence** — raw request/response bodies, which may include real tokens, PII, or internal data captured during the scan. Only commit a report deliberately as PR evidence, and check what's in it first. |

**Rule of thumb:** if a file's contents let someone log in to something or spend someone's money, it doesn't go in git — it gets injected at runtime from the CI secret store instead.

## Why committing the real auth file (or `.env`) is a real risk, not a theoretical one

- **Git history is permanent by default.** A credential committed once and "removed" in a later commit is still sitting in every clone and in the git log unless you rewrite history — which most teams never actually do.
- **CI runners and forks widen the blast radius.** A GitHub Actions workflow on a public or semi-public repo can be triggered by a PR from a fork; if secrets are hardcoded in tracked files rather than injected via `secrets.*`, anyone who can open a PR can potentially read them out in workflow logs.
- **It's a credential for a *real* account somewhere**, even if it's "just a test account." Test accounts often have access to shared staging data, shared infrastructure, or get promoted to have broader access over time as environments evolve — and don't assume test-account compromise is harmless.
- **The Cerebras key is billable.** A leaked key isn't just an access risk, it's a direct cost risk — anyone with it can run inference on your account until you notice and rotate it.

This is exactly why the README's pattern is: commit a *template* auth file with placeholders, and materialize the real one from CI secrets at job start (`envsubst` / a heredoc step) — the real values never touch a tracked file.

## Why UAT/dev is a safer target than production

- **Business-logic and injection checks are semi-destructive by design.** `rateLimiting/bruteForce` fires 10 parallel requests; `injection/sqliXss` and `injection/pathTraversal` actively fuzz fields with attack payloads; mass-assignment checks try to write privileged fields (`role`, `isAdmin`). Running this against prod risks tripping real alerting, real rate limits/bans, or — worst case — actually succeeding and mutating real data if a control is genuinely broken.
- **Multi-role auth scans use real login flows.** If the roles map to real accounts, you're authenticating as those accounts repeatedly across a full checklist run — noisy and risky against a prod IdP/rate limiter.
- **A `FAIL` in UAT is safe to leave failing while you fix it; a `FAIL` in prod is a live vulnerability sitting exposed** for as long as it takes to patch. You want to find and fix the header/CORS/auth gaps *before* they're internet-facing against real user data, not after.
- **UAT/dev is expected to be poked at.** Alerting, on-call, and data sensitivity are all calibrated for that — a burst of fuzzing traffic and 10x parallel requests from a CI job is a Tuesday, not an incident.

Practical takeaway for the team: point `--base-url`/the auth file's `login_endpoint` at staging/UAT in every CI config, gate merges to `main` on that, and only ever run APInspect against production manually, deliberately, with an actual authorized security-testing sign-off — never wired into an automatic pipeline trigger.

## Checklist for a dev setting this up for the first time

1. Add the API definition file (Postman/OpenAPI/etc.) to the repo, committed normally.
2. Write `ci/apinspect_auth.template.json` with placeholders, commit it.
3. Add the real values (`STUDENT_PASSWORD`, `LOGIN_ENDPOINT`, `CEREBRAS_API_KEY`, `STAGING_API_URL`, etc.) as encrypted CI secrets — never in a file.
4. Add a CI step that materializes the real auth file from those secrets before the scan runs, into a path that is **not** tracked by git (e.g. `ci/apinspect_auth.json`, already gitignored).
5. Point `--base-url` at staging/UAT, not production.
6. Set `--fail-on high` (or your team's threshold) so the pipeline actually blocks on real findings.
7. Upload `reports/` as a CI artifact (`if: always()`) rather than committing it, so reviewers can inspect a run without it living in git permanently.
