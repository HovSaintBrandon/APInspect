#!/usr/bin/env node
require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });

const { Command } = require('commander');
const chalk = require('chalk');
const { parse, parseRaw } = require('../core/parser');
const Engine = require('../core/engine');
const Context = require('../core/context');
const jsonReporter = require('../reporters/jsonReporter');
const checklistReporter = require('../reporters/checklistReporter');
const staticAnalyzer = require('../core/staticAnalyzer');
const newmanRunner = require('../core/newmanRunner');
const logger = require('../utils/logger');
const packageJson = require('../../package.json');
const { resolveAuthMap, authValueToHeaders } = require('./authResolver');

const program = new Command();

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
    .command('scan <file>')
    .description(
        'Scan an API definition: Postman collection or internal JSON, OpenAPI/Swagger (.json/.yaml/.yml), ' +
        'GraphQL SDL (.graphql/.gql) or a live GraphQL URL for introspection, or a gRPC .proto file'
    )
    .option('-t, --token <token>', 'Bearer token for authentication')
    .option('-u, --username <user>', 'Username for Basic Auth')
    .option('-p, --password <pass>', 'Password for Basic Auth')
    .option('-b, --base-url <url>', 'Base URL for REST/GraphQL specs, or "host:port" target for a gRPC .proto file')
    .option('--style <style>', 'API architecture style: rest, graphql, or grpc. Prompted interactively if omitted and the input file is ambiguous (Postman/OpenAPI/JSON).')
    .option('--auth-file <path>', 'Path to JSON file containing role:token mapping or login_endpoint config')
    .option('-o, --output <path>', 'Path to save report (.json, .csv, or .falcon.csv)')
    .option('--checklist', 'Run in checklist-driven mode using src/config/checklist.json + AI layer')
    .option('--cache <path>', 'Path to AI decision cache file. Generates on first run; CI reads from committed file.')
    .option('--fail-on <severity>', 'Fail with exit code 1 if any confirmed finding meets or exceeds this severity (critical, high, medium, low, info)')
    .option('--fail-on-tbc', 'Also fail on TO BE CONFIRMED findings that meet --fail-on severity (requires --fail-on)')
    .action(async (file, options) => {
        // Declared outside the try block so the catch handler can still report
        // partial results if an error is thrown mid-scan (see InfrastructureError handling below).
        const allResults = [];
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
            const config = await parse(file, options.baseUrl, cliStyle);

            // 2. Initialise AI cache (if --cache is set)
            let aiCache = null;
            if (options.cache) {
                const AICache = require('../core/ai/cache');
                aiCache = new AICache(options.cache);
            }

            // 2. Auth handling
            const authMap = await resolveAuthMap(options);

            // Run scan for each role
            for (const [role, authValue] of Object.entries(authMap)) {
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

                // 5. Generate Report
                let roleOutput = options.output;
                if (roleOutput && role !== 'default' && role !== 'unauthenticated') {
                    const path = require('path');
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
            }

            // ---------------------------------------------------------------
            // CI/CD Exit Code Evaluation
            // ---------------------------------------------------------------
            if (failOnThreshold) {
                const failingFindings = [];

                for (const r of allResults) {
                    const isFail = r.status === 'FAIL' || r.status === 'FAILED';
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
                logger.error(`\n✖ [ABORTED] Infrastructure failure: ${err.message}`);
                logger.error('  The scan was aborted. Partial results below are INCOMPLETE — do not use for gating.');
                if (allResults.length > 0) {
                    const partialPath = options.output
                        ? options.output.replace(/(\.[^.]+)?$/, '.partial$1')
                        : require('path').join(process.cwd(), 'reports', 'partial-report.json');
                    jsonReporter.generate(allResults, partialPath);
                    logger.warn(`  Partial results saved to: ${partialPath}`);
                }
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

    const cerebrasClient = require('../core/cerebrasClient');
    const userContent = relevant.map(f => ({
        header: f.header,
        status: f.status,
        value: f.value,
        message: f.message,
    }));

    const parsed = await cerebrasClient.callCerebras({
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

const writeHeaderGradeResult = (outputPath, payload) => {
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
                writeHeaderGradeResult(options.output, { url, finalUrl, ...result, ...(aiAnalyses ? { aiAnalyses } : {}) });
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
captured from a manual endpoint check. Identify concrete security issues evidenced by the response (e.g. missing/weak auth
enforcement, verbose errors or stack traces, sensitive data exposure, weak security headers, unsafe CORS, injection
indicators) and produce a short overall summary plus a list of findings, each with a risk explanation and a specific
mitigation technique. Respond with strict JSON only, matching this shape:
{ "summary": string, "findings": [ { "issue": string, "severity": "critical"|"high"|"medium"|"low"|"info", "risk": string, "mitigation": string } ] }
Base findings only on what the provided request/response actually shows. If nothing notable is present, return an empty findings array.`;

const getAiEndpointAnalysis = async ({ request, response, checkResults }) => {
    const cerebrasClient = require('../core/cerebrasClient');
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

    return cerebrasClient.callCerebras({ systemPrompt: AI_CHECK_SYSTEM_PROMPT, userContent });
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

program.parse(process.argv);
