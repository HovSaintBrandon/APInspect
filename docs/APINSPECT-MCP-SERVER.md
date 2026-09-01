# MCP server — local triage, never a gate

`src/mcp/server.js` is a separate entrypoint from the `apinspect` CLI — local, interactive, and
read-mostly. It shares its core with the declarative CLI (`src/core/runner.js`, `allowlist.js`,
`artifacts.js`) rather than owning any scan logic of its own; see
[docs/APINSPECT-DECLARATIVE-MODE.md](APINSPECT-DECLARATIVE-MODE.md) for that split's rationale.

**No tool this server exposes can produce a pass/fail verdict.** Every result is tagged
`"gating": false`. If you want a build gated on findings, that's `apinspect scan --config` — this
server is for triage after a run, chasing something suspicious, and drafting an assessment.

## Tools

| Tool | Access | What it does |
|---|---|---|
| `list_runs` | read | Lists completed `apinspect scan --config` runs, newest first, with each run's `manifest.json` summary |
| `get_findings` | read | Findings for one run, filterable by `severity` or `check_id` |
| `explain_finding` | read | Full evidence + CVSS vector for one finding, by `run_id` + `finding_id` |
| `run_check` | write | Runs named checks against one endpoint, ad hoc, against the live target |
| `diff_runs` | read | Compares two runs' FAIL findings (added/resolved/unchanged); warns if their `config_hash` differs |

`run_check` is the only tool that touches the target. The other four only read files
`apinspect scan --config` already wrote under `.apinspect/runs/` — no network access, no
side effects.

## Constraints (enforced in code, not just described in a tool's prompt text)

1. **No host argument on any tool.** `target.base_url` and `target.allowlist` come exclusively
   from `apinspect.config.yaml` in the server's working directory — reused directly from
   `src/core/configSchema.js` and `src/core/allowlist.js`, the same modules the CLI uses.
2. **`run_check` refuses any path resolving outside the allowlist, including via redirect.**
   Two layers: `httpClient.js`'s `beforeRedirect` hook (shared with the CLI, catches an
   off-allowlist *redirect target*) plus an explicit check in `run_check` itself for an
   *absolute URL* passed directly as the `path` argument — axios treats an absolute URL as
   overriding `baseURL` entirely, bypassing it without ever redirecting, which is the one
   genuinely new attack surface `run_check` introduces (every other endpoint path in this tool
   comes from a trusted config/collection file, not a live tool argument a caller controls).
   Verified live: `run_check` with `path: "https://example.com/evil"` against a target
   allowlisting only `httpbin.org` is rejected before any request is sent.
3. **Rate limited and capped per session.** 2 seconds between `run_check` calls, 20 calls per
   server process lifetime (module-level counters in `server.js` — tune there if a real triage
   session needs more headroom; they reset on server restart).
4. **Every `run_check` call is audited.** Appended as one JSON line to `.apinspect/mcp-audit.log`
   — timestamp, endpoint, method, checks, outcome. Read-only tools don't touch this log; only the
   tool that can actually affect the target does.
5. **Every result is tagged `"gating": false".** No code path in this file computes or returns a
   pass/fail verdict.

## Data handling

`get_findings`/`explain_finding` return evidence exactly as `artifacts.js` already redacted it on
the way to disk — `Authorization`/`Cookie`/`X-Api-Key` headers, plus `token`/`password`/`secret`/
`api_key`-family body fields (request *and* response — this was tightened after live testing
during this server's build surfaced a real leak: httpbin.org's `/bearer` endpoint echoes a
caller-supplied token straight back in its JSON response body, and the original redaction only
covered headers and request bodies). `run_check`'s live results go through the identical
`redactEvidence()` call before ever reaching the tool response — the model never sees a raw
secret from either path.

Evidence bodies are already capped at 2000 characters by `httpClient.js`'s exchange logger
(shared with every other path in this tool) — a full response body was never returned to begin
with, on top of the redaction above.

## Registering it

```bash
cd ~/secTest
claude mcp add apinspect -- /path/to/node /path/to/APInspect/src/mcp/server.js
claude mcp list
```

Use the **absolute** Node path (`which node`, or your nvm install's `bin/node`) — Claude Code
starts stdio servers with a different environment than your shell, and a bare `node` won't
resolve under nvm. Register it from the directory containing your project's
`apinspect.config.yaml` (e.g. `~/secTest`), since local MCP scope is tied to the directory the
`claude mcp add` command runs from — **not** `--scope project`, which writes `.mcp.json` into
that repo, and this config can name internal hosts.

### Verifying

```bash
claude mcp list    # expect: apinspect  ✔ Connected
```

If it connects but shows no tools, an environment variable the server needs is missing — pass it
with `--env KEY=value` on the `add` command (e.g. a `token_env` value if you want `run_check` to
authenticate). If it fails to connect at all, run the server command directly in your terminal:
if it starts and sits waiting on stdin (no immediate crash/exit), the server itself is fine and
the registration command is what's wrong.

## What's still open

- **`diff_runs`'s baseline strategy** isn't automated — you pass both `run_id`s explicitly today.
  The declarative-CLI plan's suggested default (last completed run on `main` with a matching
  `config_hash`) needs a way to know which run *was* on `main`, which isn't tracked yet.
- **A real MCP client hasn't exercised this yet** — everything above was verified by speaking
  the stdio JSON-RPC protocol directly (`initialize` → `tools/list` → `tools/call`) via a test
  harness, not through `claude mcp add` + an actual Claude Code session. Register it and try a
  real triage conversation before relying on it.
