#!/usr/bin/env node
const path = require('node:path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const { Command } = require('commander');
const chalk = require('chalk');
const { parse, parseRaw } = require('../core/parser');
const Engine = require('../core/engine');
const Context = require('../core/context');
const jsonReporter = require('../reporters/jsonReporter');
const checklistReporter = require('../reporters/checklistReporter');
const simplifiedReporter = require('../reporters/simplifiedReporter');
const staticAnalyzer = require('../core/staticAnalyzer');
const newmanRunner = require('../core/newmanRunner');
const logger = require('../utils/logger');
const packageJson = require('../../package.json');
const { resolveAuthMap, authValueToHeaders, assertLooksLikeToken } = require('./authResolver');
const { getCallCount } = require('../core/openrouterClient');
const { isFail: isFailStatus, COVERAGE_GAP_STATUSES } = require('../core/statuses');

const program = new Command();

// Turns a Postman collection/folder name or spec file name into a filesystem-safe
// directory name for default scan reports — see the `scan` command's baseOutput.
const sanitizeForPath = (name) => {
    const slug = (name || '')
        .toString()
        .trim()
        .replace(/[^a-zA-Z0-9._-]+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^[.-]+|[.-]+$/g, '');
    return slug || 'scan';
};

const runTimestamp = () => new Date().toISOString().replace(/[:.]/g, '-');

program
    .name('apinspect')
    .description('APInspect - API Security Checklist Scanner')
    .version(packageJson.version);

program
    .command('audit <file>')
    .description('Run Postman collection via Newman and audit responses for leaks')
    .option('-e, --env <path>', 'Postman Environment file')
    .action((file, options) => {
        try {
            // Initialize a minimal context so evidenceStore exists before
            // newman fires — prevents race conditions on ordering assumptions.
            const auditContext = new Context({
                base_url: '',
                endpoints: [],
            });
            newmanRunner.runAudit(file, options.env, auditContext);
        } catch (err) {
            logger.error(`Audit failed: ${err.message}`);
            process.exit(1);
        }
    });

program
    .command('analyze <file>')
    .description('Perform static security analysis on a Postman collection')
    .action(async (file) => {
        try {
            const rawData = await parseRaw(file);
            staticAnalyzer.analyze(rawData);
        } catch (err) {
            logger.error(`Analysis failed: ${err.message}`);
            process.exit(1);
        }
    });

program
    .command('folders <file>')
    .description('List every folder in a Postman collection, at any nesting depth, with a request count per folder')
    .action((file) => {
        try {
            const fs = require('node:fs');
            const nodePath = require('node:path');
            const { getPostmanFolderGroups } = require('../core/parser');

            const absolutePath = nodePath.resolve(file);
            if (!fs.existsSync(absolutePath)) {
                throw new Error(`File not found: ${file}`);
            }
            const rawData = JSON.parse(fs.readFileSync(absolutePath, 'utf-8'));
            if (!(rawData.info && rawData.info._postman_id)) {
                throw new Error('Not a Postman collection (missing info._postman_id).');
            }

            const groups = getPostmanFolderGroups(rawData.item || []);
            if (groups.length === 0) {
                const total = (rawData.item || []).filter(i => i.request).length;
                logger.info(`No folders — ${total} request(s) at the root of the collection.`);
                return;
            }

            logger.title(`Folders in ${nodePath.basename(absolutePath)}:`);
            groups.forEach((g, i) => {
                const indent = '  '.repeat(g.depth - 1);
                logger.info(`  ${i + 1}) ${indent}${g.name} (${g.count} request${g.count === 1 ? '' : 's'})`);
            });
            logger.info(
                '\nScope a scan to one or more with: apinspect scan <file> --folder "<name>" ' +
                '(a parent folder scans everything inside it; an indented subfolder scans just that slice — ' +
                'use "Parent/Child" if the same name appears under more than one parent)'
            );
        } catch (err) {
            logger.error(`Failed to list folders: ${err.message}`);
            process.exit(1);
        }
    });

// -----------------------------------------------------------------------------
// Abort handling — an InfrastructureError mid-scan means whatever ran before it
// is still real evidence, just incomplete. printPartialResultsSummary recaps it
// on the console (the live log already streamed every result, but by the time
// an abort happens that's scrolled past); writeAbortLog persists the full
// forensic detail (error, stack, which endpoint was in flight, sanitized CLI
// args) to an append-only file so a history of aborts survives across runs.
// -----------------------------------------------------------------------------
const printPartialResultsSummary = (results) => {
    if (results.length === 0) {
        logger.warn('  No results were recorded before the abort.');
        return;
    }

    const countByStatus = (status) => results.filter(r => r.status === status).length;
    const gaps = results.filter(r => COVERAGE_GAP_STATUSES.includes(r.status)).length;
    const knownStatuses = new Set(['PASS', 'WARN', 'TO BE CONFIRMED', 'MANUAL', 'N/A', ...COVERAGE_GAP_STATUSES]);
    const failCount = results.filter(r => isFailStatus(r.status)).length;
    const otherCount = results.filter(r => !isFailStatus(r.status) && !knownStatuses.has(r.status)).length;

    logger.title(`\nPartial Results Summary (${results.length} check(s) recorded before the abort):`);
    logger.info(
        `  PASS: ${countByStatus('PASS')}  FAIL: ${failCount}  WARN: ${countByStatus('WARN')}  ` +
        `TO BE CONFIRMED: ${countByStatus('TO BE CONFIRMED')}  MANUAL: ${countByStatus('MANUAL')}  ` +
        `N/A: ${countByStatus('N/A')}  Coverage gaps: ${gaps}` +
        (otherCount > 0 ? `  Other: ${otherCount}` : '')
    );

    const actionable = results.filter(r => isFailStatus(r.status) || r.status === 'WARN' || r.status === 'TO BE CONFIRMED');
    if (actionable.length === 0) {
        logger.success('  No FAIL / WARN / TO BE CONFIRMED findings recorded before the abort.');
        return;
    }

    logger.title('\nActionable findings so far (FAIL / WARN / TO BE CONFIRMED):');
    for (const r of actionable) {
        const line = `[${r.status}] ${r.check} — ${r.method || ''} ${r.endpoint || ''}: ${r.message}`;
        if (isFailStatus(r.status)) logger.error(line);
        else logger.warn(line);
    }
};

// CLI flags that take a credential as their next argv element — masked before
// the abort log ever touches disk, since argv alone can't otherwise tell
// "a flag's value" from "just another string".
const ABORT_LOG_REDACT_FLAGS = new Set(['-t', '--token', '-p', '--password']);

const sanitizeArgvForLog = (argv) => {
    const sanitized = [];
    for (let i = 0; i < argv.length; i++) {
        sanitized.push(argv[i]);
        if (ABORT_LOG_REDACT_FLAGS.has(argv[i])) {
            sanitized.push('[REDACTED]');
            i++; // skip the real value we just masked
        }
    }
    return sanitized;
};

const writeAbortLog = ({ err, file, role, allResults, partialPath }) => {
    const fs = require('node:fs');
    const path = require('node:path');
    const abortLogPath = path.join(process.cwd(), 'reports', 'abortlogs.jsonl');

    const record = {
        timestamp: new Date().toISOString(),
        apinspect_version: packageJson.version,
        node_version: process.version,
        command_args: sanitizeArgvForLog(process.argv),
        input_file: file,
        role: role || null,
        endpoint_in_flight: err.scanContext?.endpoint || null,
        error: {
            name: err.name,
            message: err.message,
            reason: err.reason || null,
            stack: err.stack,
        },
        partial_results_count: allResults.length,
        partial_results_path: partialPath || null,
    };

    try {
        fs.mkdirSync(path.dirname(abortLogPath), { recursive: true });
        fs.appendFileSync(abortLogPath, `${JSON.stringify(record)}\n`);
        logger.warn(`  Detailed abort log appended to: ${abortLogPath}`);
    } catch (writeErr) {
        logger.error(`  Failed to write abort log: ${writeErr.message}`);
    }
};

// -----------------------------------------------------------------------------
// Declarative mode — `apinspect scan --config apinspect.config.yaml`. Fully
// config-driven, zero LLM calls, the only path meant to gate a CI pipeline.
// See docs/APINSPECT-DECLARATIVE-MODE.md for the config format and rationale.
// Coexists with the file-driven scan below rather than replacing it — see that
// doc for why the AI-driven --checklist path isn't going anywhere.
// -----------------------------------------------------------------------------
const DECLARATIVE_SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const runDeclarativeScan = async (configPath) => {
    const { loadConfig, resolveDeclarativeAuth } = require('../core/configSchema');
    const { createClient } = require('../utils/httpClient');
    const runner = require('../core/runner');
    const artifacts = require('../core/artifacts');

    let config, configHash;
    try {
        ({ config, configHash } = loadConfig(configPath));
    } catch (err) {
        logger.error(`Config error: ${err.message}`);
        process.exit(2);
    }

    // Validate every referenced check ID up front — fail before sending a
    // single request, not partway through a run because of a typo.
    const unknownChecks = new Set();
    for (const ep of config.endpoints) {
        for (const checkId of ep.checks) {
            if (!runner.isKnownCheck(checkId)) unknownChecks.add(checkId);
        }
    }
    if (unknownChecks.size > 0) {
        logger.error(`Unknown check ID(s) in config: ${[...unknownChecks].join(', ')}. Known checks: ${[...runner.VALID_CHECK_IDS].join(', ')}`);
        process.exit(2);
    }

    let auth;
    try {
        auth = resolveDeclarativeAuth(config);
    } catch (err) {
        logger.error(err.message);
        process.exit(err.code === 'AUTH_FAILED' ? 4 : 2);
    }

    let context;
    let client;
    try {
        context = new Context({ base_url: config.target.base_url, auth, endpoints: [] });
        client = createClient(config.target.base_url, context.getAuthHeaders(), 10000, context, config.target.allowlist);
    } catch (err) {
        // Thrown by allowlist.js when target.base_url's own host isn't in
        // target.allowlist — a config mistake, not a runtime/infra failure.
        logger.error(`Config error: ${err.message}`);
        process.exit(2);
    }

    logger.title('Initializing APInspect (declarative mode)...');
    logger.info(`Target: ${config.target.base_url}`);
    logger.info(`Config hash: ${configHash}`);

    const findings = [];
    let completed = false;
    let abortReason = null;

    try {
        for (const ep of config.endpoints) {
            for (const method of ep.methods) {
                logger.subTitle(`\nTesting Endpoint: ${ep.path} [${method}]`);
                const endpointForCheck = { path: ep.path, methods: [method], body: ep.body };
                for (const checkId of ep.checks) {
                    const finding = await runner.runCheck(checkId, endpointForCheck, context, client);
                    findings.push(finding);
                    const line = `[${finding.status}] ${finding.check_id}: ${finding.message}`;
                    if (finding.status === 'FAIL') logger.error(line);
                    else if (finding.status === 'NOT_IMPLEMENTED' || finding.status === 'MANUAL') logger.warn(line);
                    else logger.info(line);
                }
            }
        }
        completed = true;
    } catch (err) {
        abortReason = err.message;
        logger.error(`\n✖ [ABORTED] ${err.message}`);
    }

    const { runDir, manifest } = artifacts.writeRun({ config, configHash, findings, completed, abortReason });
    logger.title(`\nRun written to: ${runDir}`);
    logger.info(`Findings: ${manifest.finding_count} total, ${manifest.fail_count} FAIL`);

    if (!completed) {
        logger.error('  Run did not complete every endpoint — treat results as INCOMPLETE, not passing.');
        process.exit(config.gate.fail_on_partial ? 3 : 0);
    }

    if (config.gate.fail_on === 'none') {
        logger.success('gate.fail_on is "none" — not gating on findings.');
        process.exit(0);
    }

    const threshold = DECLARATIVE_SEVERITY_ORDER[config.gate.fail_on];
    const gatingFindings = findings.filter(f => f.status === 'FAIL' && (DECLARATIVE_SEVERITY_ORDER[f.severity] ?? 3) <= threshold);
    const totalFailCount = findings.filter(f => f.status === 'FAIL').length;
    const maxExceeded = config.gate.max_new_findings !== null && totalFailCount > config.gate.max_new_findings;

    if (gatingFindings.length > 0 || maxExceeded) {
        logger.error(
            `\n✖ Gate failed: ${gatingFindings.length} finding(s) at or above "${config.gate.fail_on}"` +
            (maxExceeded ? `; total FAIL count ${totalFailCount} exceeds max_new_findings (${config.gate.max_new_findings})` : '') +
            '.'
        );
        process.exit(1);
    }

    logger.success(`\n✔ Gate passed: no findings at or above "${config.gate.fail_on}".`);
    process.exit(0);
};

program
    .command('scan [file]')
    .description(
        'Scan an API definition: Postman collection or internal JSON, OpenAPI/Swagger (.json/.yaml/.yml), ' +
        'GraphQL SDL (.graphql/.gql) or a live GraphQL URL for introspection, or a gRPC .proto file. ' +
        'Or pass --config for declarative mode (config-driven, no LLM calls) — see docs/APINSPECT-DECLARATIVE-MODE.md'
    )
    .option('-t, --token <token>', 'Bearer token for authentication')
    .option('-r, --refresh <token>', 'Refresh token — renews the bearer token automatically if it expires mid-scan (requires --token)')
    .option('--token-url <url>', 'OAuth2/OIDC token endpoint used to redeem --refresh. Defaults to the standard Keycloak endpoint derived from the access token\'s "iss" claim.')
    .option('--client-id <id>', 'OAuth2 client_id used to redeem --refresh. Defaults to the access token\'s "azp"/"client_id" claim.')
    .option('--client-secret <secret>', 'OAuth2 client_secret, only needed for a confidential client')
    .option('-u, --username <user>', 'Username for Basic Auth')
    .option('-p, --password <pass>', 'Password for Basic Auth')
    .option('-b, --base-url <url>', 'Base URL for REST/GraphQL specs, or "host:port" target for a gRPC .proto file')
    .option('--style <style>', 'API architecture style: rest, graphql, or grpc. Prompted interactively if omitted and the input file is ambiguous (Postman/OpenAPI/JSON).')
    .option('-f, --folder <name...>', 'Restrict a Postman collection scan to specific folder(s) by name, at any nesting depth (repeatable) — pass "Parent/Child" to target a subfolder whose name alone is ambiguous. Prompted interactively if omitted and the collection has folders.')
    .option('--auth-file <path>', 'Path to JSON file containing role:token mapping or login_endpoint config')
    .option('-o, --output <path>', 'Path to save report (.json, .csv, or .falcon.csv)')
    .option('--checklist', 'Run in checklist-driven mode using src/config/checklist.json + AI layer')
    .option('--classification <text>', 'Classification banner (e.g. "C2 - Internal") stamped on the simplified report emitted alongside every --checklist run')
    .option('--cache <path>', 'Path to AI decision cache file. Generates on first run; CI reads from committed file.')
    .option('--fail-on <severity>', 'Fail with exit code 1 if any confirmed finding meets or exceeds this severity (critical, high, medium, low, info)')
    .option('--fail-on-tbc', 'Also fail on TO BE CONFIRMED findings that meet --fail-on severity (requires --fail-on)')
    .option('--config <path>', 'Run in declarative mode against apinspect.config.yaml — config-driven, zero LLM calls, the only mode meant to gate CI. Mutually exclusive with a positional file.')
    .action(async (file, options) => {
        if (options.config) {
            if (file) {
                logger.error('Cannot combine a positional file argument with --config — declarative mode takes its target and endpoints entirely from the config file.');
                process.exit(2);
            }
            await runDeclarativeScan(options.config);
            return;
        }
        if (!file) {
            logger.error('Provide a file to scan, or --config <path> for declarative mode.');
            process.exit(2);
        }

        // Declared outside the try block so the catch handler can still report
        // partial results if an error is thrown mid-scan (see InfrastructureError handling below).
        const allResults = [];
        let currentRole = null;
        let baseOutput = null;
        try {
            logger.title('Initializing APInspect...');

            // Validate --fail-on / --fail-on-tbc combination
            const SEVERITY_ORDER = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4 };
            if (options.failOnTbc && !options.failOn) {
                logger.error('--fail-on-tbc requires --fail-on to be set. Example: --fail-on high --fail-on-tbc');
                process.exit(2);
            }
            if (options.failOn && !(options.failOn.toLowerCase() in SEVERITY_ORDER)) {
                logger.error(`Invalid --fail-on severity: "${options.failOn}". Valid values: critical, high, medium, low, info`);
                process.exit(2);
            }
            const failOnThreshold = options.failOn ? options.failOn.toLowerCase() : null;

            // Validate --style if provided
            const VALID_STYLES = ['rest', 'graphql', 'grpc'];
            if (options.style && !VALID_STYLES.includes(options.style.toLowerCase())) {
                logger.error(`Invalid --style: "${options.style}". Valid values: rest, graphql, grpc`);
                process.exit(2);
            }
            const cliStyle = options.style ? options.style.toLowerCase() : null;

            // 1. Parse Input
            const config = await parse(file, options.baseUrl, cliStyle, options.folder);

            // Shared across every role's simplified report so a multi-role run stamps
            // one consistent date rather than drifting across roles/minutes.
            const scanDate = new Date();

            // Default report path (no -o given): reports/<collection-or-folder-name>/report-<timestamp>.json.
            // The directory tracks the collection/folder being scanned so repeat scans of the
            // same input land together; the file name is unique per run so they don't clobber
            // each other the way a fixed reports/report.json would.
            baseOutput = options.output || path.join(process.cwd(), 'reports', sanitizeForPath(config.scanName), `report-${runTimestamp()}.json`);

            // 2. Initialise AI cache (if --cache is set)
            let aiCache = null;
            if (options.cache) {
                const AICache = require('../core/ai/cache');
                aiCache = new AICache(options.cache);
            }

            // 2. Auth handling
            const authMap = await resolveAuthMap(options, config.collectionAuth);

            // Run scan for each role
            for (const [role, authValue] of Object.entries(authMap)) {
                currentRole = role;
                if (role !== 'default' && role !== 'unauthenticated') {
                    logger.title(`\n=== Starting scan for role: ${role.toUpperCase()} ===`);
                    config.auth = (typeof authValue === 'string') ? { type: 'bearer', token: authValue } : authValue;
                } else if (role === 'default') {
                    config.auth = authValue;
                } else {
                    delete config.auth;
                }

                // 3. Initialize Engine
                const engine = new Engine(config);

                // Wire in the AI cache if available
                if (aiCache) engine.setCache(aiCache);

                if (options.checklist) {
                    // Checklist-driven mode: FALCON checklist + AI applicability/synthesis/classification
                    engine.loadChecklist();
                    if (role === 'default' || role === 'unauthenticated' || role === Object.keys(authMap)[0]) {
                        logger.info('Checklist mode active — FALCON AI-driven scan.');
                    }
                } else {
                    // Legacy mode: flat hardcoded check list
                    engine.loadChecks();
                }

                // Phase 1: Run Initial Discovery
                const { runDiscovery } = require('../core/discovery');
                await runDiscovery(engine.context, engine.client);

                // 4. Run Scan (Phase 2)
                const results = await engine.run();
                allResults.push(...results);

                // Run-level degradations (e.g. the AI provider ran out of balance
                // partway through) are also embedded as a "system/aiProbeSynthesis"
                // result above, but surface them here too so they aren't easy to miss
                // in a long scrollback — the scan still completed, just not fully.
                for (const warning of engine.context.getWarnings()) {
                    logger.error(`\n⚠ [${role}] ${warning}`);
                }

                if (options.checklist) {
                    const na = results.filter(r => r.status === 'N/A').length;
                    const applicable = results.length - na;
                    const evaluated = results.filter(r => r.status === 'PASS' || isFailStatus(r.status)).length;
                    const gaps = results.filter(r => COVERAGE_GAP_STATUSES.includes(r.status)).length;
                    const coveragePct = applicable > 0 ? Math.round((evaluated / applicable) * 1000) / 10 : 0;
                    logger.info(
                        `[${role}] Coverage: ${evaluated}/${applicable} applicable checks evaluated (${coveragePct}%)` +
                        (gaps > 0 ? ` — ${gaps} blocked by auth/routing/endpoint health, see report for detail.` : '.')
                    );
                }

                // 5. Generate Report
                let roleOutput = baseOutput;
                if (role !== 'default' && role !== 'unauthenticated') {
                    const parsed = path.parse(roleOutput);
                    if (parsed.base.endsWith('.falcon.csv')) {
                        roleOutput = path.join(parsed.dir, parsed.base.replace('.falcon.csv', `.${role}.falcon.csv`));
                    } else {
                        roleOutput = path.join(parsed.dir, `${parsed.name}.${role}${parsed.ext}`);
                    }
                }

                if (roleOutput && roleOutput.endsWith('.falcon.csv')) {
                    // FALCON review spreadsheet format
                    checklistReporter.generate(results, roleOutput);
                } else if (roleOutput && roleOutput.endsWith('.csv')) {
                    const csvReporter = require('../reporters/csvReporter');
                    csvReporter.generate(results, roleOutput);
                } else {
                    // Default to JSON
                    jsonReporter.generate(results, roleOutput);
                }

                // Simplified report: always written alongside the primary report in
                // checklist mode — a flat, client-facing audit matrix pivoted off the
                // same checklist items, next to whichever primary format was chosen above.
                if (options.checklist) {
                    const parsedRole = path.parse(roleOutput);
                    const stem = parsedRole.base.endsWith('.falcon.csv')
                        ? parsedRole.base.slice(0, -'.falcon.csv'.length)
                        : parsedRole.name;
                    const simplifiedOutput = path.join(parsedRole.dir, `simplified-${stem}.json`);

                    simplifiedReporter.generate(results, simplifiedOutput, {
                        project: config.scanName,
                        classification: options.classification || '',
                        date: scanDate,
                    });
                }
            }

            if (options.checklist) {
                logger.info(`\nAI calls made this run: ${getCallCount()}`);
            }

            // ---------------------------------------------------------------
            // CI/CD Exit Code Evaluation
            // ---------------------------------------------------------------
            if (failOnThreshold) {
                const failingFindings = [];

                for (const r of allResults) {
                    const isFail = isFailStatus(r.status);
                    const isWarn = r.status === 'WARN';
                    const isTbc = r.confirmation_status === 'to_be_confirmed';
                    const isActionable = isFail || isWarn;

                    // Skip non-actionable results
                    if (!isActionable && !isTbc) continue;

                    // Check if this finding's severity meets the threshold
                    const findingSeverity = (r.severity || 'Info').toLowerCase();
                    const meetsSeverity = (SEVERITY_ORDER[findingSeverity] ?? 4) <= SEVERITY_ORDER[failOnThreshold];
                    if (!meetsSeverity) continue;

                    if (isTbc) {
                        // TBC findings only count if --fail-on-tbc is set
                        if (options.failOnTbc) {
                            failingFindings.push(r);
                        }
                    } else {
                        // Confirmed failing/warning findings
                        failingFindings.push(r);
                    }
                }

                if (failingFindings.length > 0) {
                    // Group by severity for the summary
                    const bySeverity = {};
                    for (const f of failingFindings) {
                        const sev = f.severity || 'Info';
                        bySeverity[sev] = (bySeverity[sev] || 0) + 1;
                    }
                    const tbcCount = failingFindings.filter(f => f.confirmation_status === 'to_be_confirmed').length;
                    const confirmedCount = failingFindings.length - tbcCount;

                    const parts = Object.entries(bySeverity).map(([sev, count]) => `${count} ${sev}`);
                    logger.error(`\n✖ CI/CD Failure: ${parts.join(', ')} finding(s) at or above "${failOnThreshold}" threshold.`);
                    if (confirmedCount > 0) logger.error(`  Confirmed: ${confirmedCount}`);
                    if (tbcCount > 0) logger.error(`  To Be Confirmed: ${tbcCount} (included via --fail-on-tbc)`);
                    process.exit(1);
                } else {
                    logger.success(`\n✔ CI/CD Gate: No findings at or above "${failOnThreshold}" threshold. Exiting cleanly.`);
                }
            }

        } catch (err) {
            if (err.name === 'InfrastructureError') {
                // Infrastructure failure — not a security finding.
                // Dump partial results so the run isn't a total loss, then abort.
                //
                // allResults only has results from roles whose engine.run() already
                // resolved — the role that was actually in flight when this error hit
                // never reached its own return, so its already-completed endpoints
                // live only on the error itself (see engine.js run()). Without folding
                // those in here too, a billing error on endpoint 31 of a 31-endpoint
                // scan would report 0 partial results instead of the 30 that finished.
                if (err.partialResults?.length > 0) allResults.push(...err.partialResults);

                logger.error(`\n✖ [ABORTED] Infrastructure failure: ${err.message}`);
                if (err.scanContext?.endpoint) logger.error(`  In flight when it aborted: ${err.scanContext.endpoint}`);
                logger.error('  The scan was aborted. Partial results below are INCOMPLETE — do not use for gating.');
                for (const warning of err.partialWarnings || []) {
                    logger.error(`  ⚠ ${warning}`);
                }

                let partialPath = null;
                if (allResults.length > 0) {
                    const target = baseOutput || path.join(process.cwd(), 'reports', 'partial-report.json');
                    partialPath = target.replace(/(\.[^.]+)?$/, '.partial$1');
                    jsonReporter.generate(allResults, partialPath);
                    logger.warn(`  Partial results saved to: ${partialPath}`);
                }

                printPartialResultsSummary(allResults);
                writeAbortLog({ err, file, role: currentRole, allResults, partialPath });

                process.exit(3); // 3 = Infrastructure/Network Failure
            }
            logger.error(`Scan failed: ${err.message}`);
            process.exit(1);
        }
    });

const headerFindingLine = (finding) => {
    const base = `${finding.header}: ${finding.message}`;
    return finding.recommendation ? `${base} → ${finding.recommendation}` : base;
};

// securityheaders.com-style grade colors: green (A) fading through yellow/orange to red (F).
const GRADE_COLORS = {
    'A+': chalk.hex('#00b34a').bold,
    'A': chalk.hex('#4caf50').bold,
    'B': chalk.hex('#8bc34a').bold,
    'C': chalk.hex('#ffc107').bold,
    'D': chalk.hex('#ff9800').bold,
    'E': chalk.hex('#ff5722').bold,
    'F': chalk.hex('#f44336').bold,
};

const colorGrade = (grade) => (GRADE_COLORS[grade] || chalk.bold)(grade);

const printHeaderGradeReport = (result, requestedUrl, finalUrl) => {
    logger.title(`\nGrade: ${colorGrade(result.grade)}  (${result.score}/100)`);
    if (finalUrl !== requestedUrl) logger.info(`Followed redirect to: ${finalUrl}`);

    for (const finding of result.findings) {
        const line = headerFindingLine(finding);
        if (finding.status === 'GOOD') logger.success(line);
        else if (finding.status === 'INFO' || finding.status === 'N/A') logger.info(line);
        else logger.warn(line);
    }
};

// Findings worth asking the AI to explain — headers that hurt the score or leak info.
const AI_RELEVANT_STATUSES = new Set(['MISSING', 'WEAK', 'LEAK']);

const AI_SYSTEM_PROMPT = `You are an application security expert reviewing HTTP security header findings.
For each finding provided, explain the concrete security risk of the issue and a specific mitigation.
Respond with strict JSON only, matching this shape:
{ "analyses": [ { "header": string, "risk": string, "mitigation": string } ] }
Keep each "risk" and "mitigation" to 1-2 concise sentences. Do not include headers that were not provided.`;

const getAiHeaderRecommendations = async (findings) => {
    const relevant = findings.filter(f => AI_RELEVANT_STATUSES.has(f.status));
    if (relevant.length === 0) return [];

    const openrouterClient = require('../core/openrouterClient');
    const userContent = relevant.map(f => ({
        header: f.header,
        status: f.status,
        value: f.value,
        message: f.message,
    }));

    const parsed = await openrouterClient.callOpenRouter({
        systemPrompt: AI_SYSTEM_PROMPT,
        userContent,
    });

    return Array.isArray(parsed?.analyses) ? parsed.analyses : [];
};

const printAiHeaderRecommendations = (analyses) => {
    if (analyses.length === 0) return;
    logger.title('\nAI Risk Analysis & Mitigations:');
    for (const item of analyses) {
        logger.subTitle(`\n${item.header}`);
        logger.warn(`Risk: ${item.risk}`);
        logger.success(`Mitigation: ${item.mitigation}`);
    }
};

// Shared by any standalone (non-Engine) command that saves its result as a single JSON
// blob — `headers` and `jwt` both write arbitrary result shapes, not Engine-style results.
const writeJsonResult = (outputPath, payload) => {
    const fs = require('node:fs');
    const path = require('node:path');
    const outPath = path.resolve(outputPath);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(payload, null, 2));
    logger.success(`\nResult saved to ${outPath}`);
};

program
    .command('headers <url>')
    .description('Grade the security headers of a single URL (securityheaders.com-style), without running a full scan')
    .option('-t, --token <token>', 'Bearer token for authentication')
    .option('-u, --username <user>', 'Username for Basic Auth')
    .option('-p, --password <pass>', 'Password for Basic Auth')
    .option('--auth-file <path>', 'Path to JSON file containing role:token mapping or login_endpoint config')
    .option('-o, --output <path>', 'Path to save the grading result as JSON')
    .option('-AI, --ai', 'Include AI-generated risk analysis and mitigations for weak/missing headers')
    .action(async (url, options) => {
        try {
            const axios = require('axios');
            const authMap = await resolveAuthMap(options);
            const authHeaders = authValueToHeaders(authMap.default);

            logger.title(`Fetching headers for ${url}...`);
            const response = await axios.get(url, {
                headers: authHeaders,
                maxRedirects: 10, // follow to the final destination — grade that, not the 30x hop
                validateStatus: () => true,
            });

            // Node's http client records the post-redirect URL at res.responseUrl.
            const finalUrl = response.request?.res?.responseUrl || url;
            const isHttps = finalUrl.startsWith('https');

            const headerGrader = require('../core/headerGrader');
            const result = headerGrader.grade(response.headers, { isHttps });

            printHeaderGradeReport(result, url, finalUrl);

            let aiAnalyses;
            if (options.ai) {
                try {
                    aiAnalyses = await getAiHeaderRecommendations(result.findings);
                    printAiHeaderRecommendations(aiAnalyses);
                } catch (aiErr) {
                    logger.error(`AI recommendation request failed: ${aiErr.message}`);
                }
            }

            if (options.output) {
                writeJsonResult(options.output, { url, finalUrl, ...result, ...(aiAnalyses ? { aiAnalyses } : {}) });
            }
        } catch (err) {
            logger.error(`Header grading failed: ${err.message}`);
            process.exit(1);
        }
    });

// -----------------------------------------------------------------------------
// `check` — full hardcoded-check sweep against a single live endpoint, no
// collection/spec file required. Everything the endpoint needs (method, extra
// headers, body, auth) is passed directly on the command line.
// -----------------------------------------------------------------------------
const parseHeaderList = (headerList = []) => {
    const headers = {};
    for (const entry of headerList) {
        const idx = entry.indexOf(':');
        if (idx === -1) {
            throw new Error(`Invalid --header value "${entry}" — expected "Key: Value"`);
        }
        headers[entry.slice(0, idx).trim()] = entry.slice(idx + 1).trim();
    }
    return headers;
};

const parseBodyOption = (data) => {
    if (!data) return undefined;
    const fs = require('node:fs');
    const raw = data.startsWith('@') ? fs.readFileSync(data.slice(1), 'utf8') : data;
    try {
        return JSON.parse(raw);
    } catch (e) {
        return raw;
    }
};

const AI_CHECK_SYSTEM_PROMPT = `You are an application security expert analyzing a single live HTTP request/response exchange
captured from a manual endpoint check, alongside the verdicts of deterministic security checks already run against it.
Identify concrete security issues evidenced by the response (e.g. missing/weak auth enforcement, verbose errors or stack
traces, sensitive data exposure, weak security headers, unsafe CORS, injection indicators) and produce a short overall
summary plus a list of findings, each with a risk explanation and a specific mitigation technique.

Strict evidence rules:
- Only report a finding as a confirmed issue if the request/response actually demonstrates it. A non-2xx response
  (e.g. a 400 for a missing required field) is NOT evidence that authentication/authorization is missing or bypassed —
  it only shows the request was malformed or incomplete.
- Do not restate a check whose status is "MANUAL" or "TO BE CONFIRMED" as if it were a confirmed vulnerability — if you
  mention it at all, keep its severity at "info" and phrase it as needing manual verification, not as a confirmed finding.
- Do not flag "missing authentication" on an endpoint whose purpose is to authenticate (e.g. login/token/refresh
  endpoints) — those are expected to be reachable without a prior session.
- If the endpoint requires a request body or headers to be evaluated meaningfully and none were supplied, say so rather
  than guessing at behavior.

Respond with strict JSON only, matching this shape:
{ "summary": string, "findings": [ { "issue": string, "severity": "critical"|"high"|"medium"|"low"|"info", "risk": string, "mitigation": string } ] }
Base findings only on what the provided request/response and check results actually show. If nothing notable is present, return an empty findings array.`;

const getAiEndpointAnalysis = async ({ request, response, checkResults }) => {
    const openrouterClient = require('../core/openrouterClient');
    const userContent = {
        request,
        response: {
            status: response.status,
            headers: response.headers,
            body: typeof response.data === 'string'
                ? response.data.slice(0, 4000)
                : JSON.stringify(response.data).slice(0, 4000),
        },
        checkResults: checkResults.map(r => ({ check: r.check, status: r.status, message: r.message })),
    };

    return openrouterClient.callOpenRouter({ systemPrompt: AI_CHECK_SYSTEM_PROMPT, userContent });
};

const printAiEndpointAnalysis = (analysis) => {
    logger.title('\nAI Security Analysis:');
    logger.info(analysis.summary || '(no summary returned)');
    for (const finding of (analysis.findings || [])) {
        logger.subTitle(`\n[${(finding.severity || 'info').toUpperCase()}] ${finding.issue}`);
        logger.warn(`Risk: ${finding.risk}`);
        logger.success(`Mitigation: ${finding.mitigation}`);
    }
};

program
    .command('check <url>')
    .description('Run a full security check (auth, CORS, headers, injection, rate limiting, etc.) against a single live endpoint')
    .option('-X, --method <method>', 'HTTP method to use', 'GET')
    .option('-H, --header <header...>', 'Extra request header as "Key: Value" (repeatable)')
    .option('-d, --data <body>', 'Request body — a JSON string, or @path/to/file.json')
    .option('-t, --token <token>', 'Bearer token for authentication')
    .option('-r, --refresh <token>', 'Refresh token — renews the bearer token automatically if it expires mid-check (requires --token)')
    .option('--token-url <url>', 'OAuth2/OIDC token endpoint used to redeem --refresh. Defaults to the standard Keycloak endpoint derived from the access token\'s "iss" claim.')
    .option('--client-id <id>', 'OAuth2 client_id used to redeem --refresh. Defaults to the access token\'s "azp"/"client_id" claim.')
    .option('--client-secret <secret>', 'OAuth2 client_secret, only needed for a confidential client')
    .option('-u, --username <user>', 'Username for Basic Auth')
    .option('-p, --password <pass>', 'Password for Basic Auth')
    .option('--auth-file <path>', 'Path to JSON file containing role:token mapping or login_endpoint config')
    .option('-o, --output <path>', 'Path to save the check results as JSON')
    .option('-AI, --ai', 'Send the live request/response to the AI for a risk analysis and mitigation recommendations')
    .action(async (url, options) => {
        try {
            const parsedUrl = new URL(url);
            const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
            const path = `${parsedUrl.pathname}${parsedUrl.search}`;
            const method = options.method.toUpperCase();
            const extraHeaders = parseHeaderList(options.header);
            const body = parseBodyOption(options.data);

            const authMap = await resolveAuthMap(options);
            const config = {
                base_url: baseUrl,
                auth: authMap.default || null,
                headers: extraHeaders,
                endpoints: [{
                    path,
                    methods: [method],
                    body,
                    protocol: 'rest',
                }],
            };

            logger.title(`Checking ${method} ${url}...`);

            const Engine = require('../core/engine');
            const engine = new Engine(config);
            engine.loadChecks();
            const results = await engine.run();

            if (options.ai) {
                try {
                    const response = await engine.client.request({
                        method,
                        url: path,
                        data: body,
                    });
                    const analysis = await getAiEndpointAnalysis({
                        request: { method, url, headers: { ...extraHeaders, ...engine.context.getAuthHeaders() }, body },
                        response,
                        checkResults: results,
                    });
                    printAiEndpointAnalysis(analysis);
                    if (options.output) results.push({ check: 'ai/endpointAnalysis', ...analysis });
                } catch (aiErr) {
                    logger.error(`AI analysis failed: ${aiErr.message}`);
                }
            }

            if (options.output) {
                const jsonReporter = require('../reporters/jsonReporter');
                jsonReporter.generate(results, options.output);
            }
        } catch (err) {
            logger.error(`Check failed: ${err.message}`);
            process.exit(1);
        }
    });

// -----------------------------------------------------------------------------
// `jwt` — decode a JWT, run offline header/claims analysis, construct forgery
// attacks (alg=none, algorithm confusion, weak-secret cracking, kid injection),
// and optionally fire the forged tokens at a live authenticated endpoint to see
// which ones actually get through.
// -----------------------------------------------------------------------------
const JWT_SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const JWT_SEVERITY_LOG = {
    critical: (msg) => logger.error(msg),
    high: (msg) => logger.error(msg),
    medium: (msg) => logger.warn(msg),
    low: (msg) => logger.warn(msg),
    info: (msg) => logger.info(msg),
};

const printJwtFindings = (findings) => {
    if (findings.length === 0) {
        logger.success('No issues found in header/claims analysis.');
        return;
    }
    const sorted = [...findings].sort((a, b) => (JWT_SEVERITY_ORDER[a.severity] ?? 5) - (JWT_SEVERITY_ORDER[b.severity] ?? 5));
    for (const f of sorted) {
        const log = JWT_SEVERITY_LOG[f.severity] || logger.info;
        log(`[${f.severity.toUpperCase()}] ${f.message}`);
        if (f.recommendation) logger.info(`  → ${f.recommendation}`);
    }
};

const printJwtForgeries = (forgeries) => {
    logger.title('\nForged Tokens Constructed:');
    for (const f of forgeries) {
        logger.subTitle(`\n${f.name}`);
        logger.info(f.description);
        logger.info(f.token);
    }
};

const JWT_VERDICT_LOG = {
    accepted: (msg) => logger.error(msg),
    inconclusive: (msg) => logger.warn(msg),
    rejected: (msg) => logger.success(msg),
    error: (msg) => logger.warn(msg),
};

const printJwtLiveResults = (liveResults) => {
    logger.title('\nLive Forgery Test Results:');
    logger.info(`Baseline — no Authorization header: ${liveResults.baseline.noAuth.status}`);
    logger.info(`Baseline — original token: ${liveResults.baseline.originalToken.status}`);
    for (const attempt of liveResults.attempts) {
        const log = JWT_VERDICT_LOG[attempt.verdict.verdict] || logger.info;
        log(`${attempt.name}: ${attempt.verdict.verdict.toUpperCase()} — ${attempt.verdict.reason}`);
    }
};

const AI_JWT_SYSTEM_PROMPT = `You are an application security expert specializing in JWT (JSON Web Token) security.
You are given a decoded JWT (header + payload; the raw signature is omitted), the deterministic findings already
raised against its header/claims, and — if a live endpoint was supplied — the results of forgery attacks (alg=none,
RS/ES/PS -> HS256 algorithm confusion, weak HMAC secret cracking, kid injection) run against it.

Explain the concrete risk and a specific, actionable mitigation for each notable issue. Treat any forgery attempt
with verdict "accepted" as a confirmed critical finding — it is a demonstrated authentication bypass, not a
theoretical one. Do not invent findings unsupported by the provided data, and do not describe an "inconclusive" or
"rejected" attempt as if it had succeeded.

Respond with strict JSON only, matching this shape:
{ "summary": string, "analyses": [ { "issue": string, "severity": "critical"|"high"|"medium"|"low"|"info", "risk": string, "mitigation": string } ] }`;

const getAiJwtRecommendations = async ({ header, payload, findings, liveResults }) => {
    const openrouterClient = require('../core/openrouterClient');
    const userContent = {
        header,
        payload,
        findings: findings.map(f => ({ id: f.id, severity: f.severity, message: f.message })),
        liveForgeryResults: liveResults ? {
            baseline: liveResults.baseline,
            attempts: liveResults.attempts.map(a => ({ name: a.name, verdict: a.verdict.verdict, reason: a.verdict.reason })),
        } : null,
    };
    return openrouterClient.callOpenRouter({ systemPrompt: AI_JWT_SYSTEM_PROMPT, userContent });
};

const printAiJwtAnalysis = (analysis) => {
    logger.title('\nAI Security Analysis:');
    logger.info(analysis.summary || '(no summary returned)');
    for (const item of (analysis.analyses || [])) {
        logger.subTitle(`\n[${(item.severity || 'info').toUpperCase()}] ${item.issue}`);
        logger.warn(`Risk: ${item.risk}`);
        logger.success(`Mitigation: ${item.mitigation}`);
    }
};

program
    .command('jwt <token>')
    .description('Decode a JWT and analyze it for header/claim weaknesses, then attempt forgery attacks (alg=none, algorithm confusion, weak-secret cracking, kid injection) — optionally against a live authenticated endpoint')
    .option('-e, --endpoint <url>', 'Authenticated endpoint to test forged tokens against. Without this, forged tokens are constructed and reported but never sent anywhere.')
    .option('-X, --method <method>', 'HTTP method to use against --endpoint', 'GET')
    .option('-H, --header <header...>', 'Extra request header as "Key: Value" (repeatable)')
    .option('--public-key <path>', 'Path to a PEM public key file — enables the RS/ES/PS -> HS256 algorithm-confusion attack')
    .option('--wordlist <path>', 'Path to a newline-delimited wordlist for HMAC secret cracking (merged with the built-in common-secrets list)')
    .option('--extend-exp <minutes>', 'On every re-signable forgery (algorithm confusion, kid injection, cracked-secret), also push the "exp" claim forward this many minutes from now — tests whether the server enforces token lifetime server-side rather than trusting the client-supplied exp. Omit to leave exp untouched (cracked-secret forgery still defaults to its own 10-year push).')
    .option('-o, --output <path>', 'Path to save the full analysis as JSON')
    .option('-AI, --ai', 'Include AI-generated risk analysis and mitigation recommendations')
    .action(async (token, options) => {
        try {
            const fs = require('node:fs');
            const { decode } = require('../core/jwt/jwtCodec');
            const { analyzeHeader, analyzeClaims } = require('../core/jwt/jwtStaticAnalysis');
            const {
                crackHmacSecret, forgeAlgNone, forgeAlgConfusion, forgeKidInjection, forgeWithCrackedSecret,
            } = require('../core/jwt/jwtForge');

            let extendExpMinutes;
            if (options.extendExp !== undefined) {
                extendExpMinutes = Number(options.extendExp);
                if (!Number.isFinite(extendExpMinutes)) {
                    logger.error(`Invalid --extend-exp value: "${options.extendExp}" — must be a number of minutes.`);
                    process.exit(2);
                }
            }

            const decoded = decode(token);

            logger.title('Decoded Header:');
            console.log(JSON.stringify(decoded.header, null, 2));
            logger.title('\nDecoded Payload:');
            console.log(JSON.stringify(decoded.payload, null, 2));

            // 1. Static header/claims analysis
            const findings = [...analyzeHeader(decoded.header), ...analyzeClaims(decoded.payload)];

            // 2. Weak HMAC secret cracking (only applicable to HS256/384/512 tokens)
            const builtinWordlist = require('../config/commonJwtSecrets.json');
            let wordlist = builtinWordlist;
            if (options.wordlist) {
                const custom = fs.readFileSync(options.wordlist, 'utf8')
                    .split(/\r?\n/).map(l => l.trim()).filter(Boolean);
                wordlist = [...new Set([...builtinWordlist, ...custom])];
            }
            const crackedSecret = crackHmacSecret(decoded, wordlist);
            if (crackedSecret !== null) {
                findings.push({
                    id: 'JWT-HMAC-SECRET-CRACKED',
                    severity: 'critical',
                    field: 'signature',
                    message: `HMAC secret cracked using a ${wordlist.length}-entry wordlist: "${crackedSecret === '' ? '(empty string)' : crackedSecret}". Anyone with this secret can forge arbitrary valid tokens.`,
                    recommendation: 'Rotate the signing secret immediately and use a high-entropy, randomly generated secret (32+ bytes) going forward.',
                });
            }

            logger.title('\nStatic Findings:');
            printJwtFindings(findings);

            // 3. Construct forgeries (offline — no network yet)
            const forgeries = [...forgeAlgNone(decoded, extendExpMinutes)];

            let publicKeyPem = null;
            if (options.publicKey) publicKeyPem = fs.readFileSync(options.publicKey, 'utf8');
            const confusionForgery = forgeAlgConfusion(decoded, publicKeyPem, extendExpMinutes);
            if (confusionForgery) forgeries.push(confusionForgery);

            forgeries.push(...forgeKidInjection(decoded, extendExpMinutes));

            if (crackedSecret !== null) {
                forgeries.push(forgeWithCrackedSecret(decoded, crackedSecret, extendExpMinutes));
            }

            printJwtForgeries(forgeries);

            // 4. Live testing against a real endpoint (optional)
            let liveResults = null;
            if (options.endpoint) {
                const { runLiveForgeryTests } = require('../core/jwt/jwtLiveTester');
                const extraHeaders = parseHeaderList(options.header);
                const method = options.method.toUpperCase();

                const liveForgeries = [...forgeries];
                if (decoded.payload.exp !== undefined && decoded.payload.exp < Math.floor(Date.now() / 1000)) {
                    liveForgeries.push({
                        name: 'expired-token-replay',
                        description: 'Original token is already expired (exp in the past) — resent unmodified to check whether the server actually enforces "exp".',
                        token,
                    });
                }

                logger.title(`\nRunning live forgery tests against ${method} ${options.endpoint}...`);
                liveResults = await runLiveForgeryTests({
                    url: options.endpoint,
                    method,
                    headers: extraHeaders,
                    originalToken: token,
                    forgeries: liveForgeries,
                });
                printJwtLiveResults(liveResults);

                for (const attempt of liveResults.attempts) {
                    if (attempt.verdict.verdict === 'accepted') {
                        findings.push({
                            id: 'JWT-FORGERY-ACCEPTED',
                            severity: 'critical',
                            field: attempt.name,
                            message: `Endpoint accepted a forged token via "${attempt.name}" — ${attempt.verdict.reason}`,
                            recommendation: 'Fix the underlying verification gap for this attack class before deploying — forged tokens must be rejected.',
                        });
                    }
                }
            } else {
                logger.info('\nNo --endpoint given — forged tokens above were constructed but not sent anywhere. Pass --endpoint <authenticated-url> to test them live.');
            }

            // 5. AI recommendations (optional)
            let aiAnalysis = null;
            if (options.ai) {
                try {
                    aiAnalysis = await getAiJwtRecommendations({ header: decoded.header, payload: decoded.payload, findings, liveResults });
                    printAiJwtAnalysis(aiAnalysis);
                } catch (aiErr) {
                    logger.error(`AI analysis failed: ${aiErr.message}`);
                }
            }

            // 6. Output
            if (options.output) {
                writeJsonResult(options.output, {
                    header: decoded.header,
                    payload: decoded.payload,
                    findings,
                    forgeries,
                    liveResults,
                    ...(aiAnalysis ? { aiAnalysis } : {}),
                });
            }
        } catch (err) {
            logger.error(`JWT analysis failed: ${err.message}`);
            process.exit(1);
        }
    });

// -----------------------------------------------------------------------------
// `refresh` — standalone token-refresh daemon. Independent of `scan`'s mid-scan
// auto-refresh (Context#ensureFreshToken) — this just keeps one access token
// alive in your terminal (and optionally a file) for as long as the process runs,
// e.g. to feed into another tool, a second terminal, or manual curl/Postman use.
// -----------------------------------------------------------------------------
program
    .command('refresh')
    .description('Continuously refresh a bearer token via its refresh token, printing (and optionally saving) a fresh access token each time the old one is about to expire. Runs until you stop it with Ctrl+C.')
    .requiredOption('-t, --token <token>', 'Current access token (must be a JWT with an "exp" claim)')
    .requiredOption('-r, --refresh <token>', 'Refresh token used to renew the access token')
    .option('--token-url <url>', 'OAuth2/OIDC token endpoint. Defaults to the standard Keycloak endpoint derived from the access token\'s "iss" claim.')
    .option('--client-id <id>', 'OAuth2 client_id. Defaults to the access token\'s "azp"/"client_id" claim.')
    .option('--client-secret <secret>', 'OAuth2 client_secret, only needed for a confidential client')
    .option('-o, --output <path>', 'File to overwrite with the current access token on every refresh — point another tool at this path to always read a live token')
    .action(async (options) => {
        try {
            assertLooksLikeToken(options.token, 'token');
            assertLooksLikeToken(options.refresh, 'refresh');
        } catch (err) {
            logger.error(err.message);
            process.exit(2);
        }

        const fs = require('node:fs');
        const path = require('node:path');
        const { decode } = require('../core/jwt/jwtCodec');
        const { refreshAccessToken, REFRESH_SKEW_SECONDS } = require('../core/jwt/tokenRefresher');

        // Floor on how soon we'll fire the *next* refresh after one just completed.
        // Without it, a token whose actual lifetime is shorter than REFRESH_SKEW_SECONDS
        // (misconfigured IdP, a non-Keycloak issuer with short-lived tokens, clock drift)
        // makes every scheduled wait compute to ~0ms — a busy loop hammering the token
        // endpoint as fast as the event loop allows instead of a periodic refresh.
        const MIN_REFRESH_INTERVAL_MS = 5000;

        // Throws if `token` isn't a decodable JWT or has no "exp" claim to schedule against.
        const expiryOf = (token) => {
            let payload;
            try {
                ({ payload } = decode(token));
            } catch (err) {
                throw new Error(`Not a decodable JWT: ${err.message}`);
            }
            if (!payload.exp) {
                throw new Error('Token has no "exp" claim — nothing to schedule a refresh against.');
            }
            return payload.exp;
        };

        const writeOutputFile = (token) => {
            if (!options.output) return;
            const outPath = path.resolve(options.output);
            try {
                fs.mkdirSync(path.dirname(outPath), { recursive: true, mode: 0o700 });
                // This file holds a live bearer token — owner-only. `mode` on writeFileSync
                // only applies when the file is first created, so an existing file (made
                // earlier under a looser umask, or by something else) is chmod'd explicitly
                // on every write too, since we overwrite this same path on every refresh.
                fs.writeFileSync(outPath, token, { mode: 0o600 });
                fs.chmodSync(outPath, 0o600);
            } catch (err) {
                logger.error(`Failed to write token to ${outPath}: ${err.message}`);
            }
        };

        let currentToken = options.token;
        let currentRefreshToken = options.refresh;
        let exp;
        try {
            exp = expiryOf(currentToken);
        } catch (err) {
            logger.error(err.message);
            process.exit(2);
        }

        logger.title('Token refresh loop started — Ctrl+C to stop.');
        logger.info(`Access token expires at ${new Date(exp * 1000).toISOString()}`);
        writeOutputFile(currentToken);

        process.on('SIGINT', () => {
            logger.info('\nStopped.');
            process.exit(0);
        });

        // Runs until the process is killed — each iteration sleeps until just before
        // the current token expires, refreshes, prints/saves the new one, and repeats
        // with the (possibly rotated — Keycloak rotates by default) refresh token.
        for (;;) {
            const waitMs = Math.max(MIN_REFRESH_INTERVAL_MS, (exp - REFRESH_SKEW_SECONDS) * 1000 - Date.now());
            logger.info(`Next refresh in ${Math.round(waitMs / 1000)}s...`);
            await new Promise(resolve => setTimeout(resolve, waitMs));

            try {
                const result = await refreshAccessToken({
                    currentToken,
                    refreshToken: currentRefreshToken,
                    tokenUrl: options.tokenUrl,
                    clientId: options.clientId,
                    clientSecret: options.clientSecret,
                });
                currentToken = result.accessToken;
                currentRefreshToken = result.refreshToken;
                exp = expiryOf(currentToken);

                logger.success(`Refreshed at ${new Date().toISOString()} — new token expires ${new Date(exp * 1000).toISOString()}`);
                console.log(currentToken);
                writeOutputFile(currentToken);
            } catch (err) {
                logger.error(`Token refresh failed: ${err.message}`);
                process.exit(1);
            }
        }
    });

program.parse(process.argv);
