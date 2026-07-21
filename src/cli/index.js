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

const printHeaderGradeReport = (result, requestedUrl, finalUrl) => {
    logger.title(`\nGrade: ${result.grade}  (${result.score}/100)`);
    if (finalUrl !== requestedUrl) logger.info(`Followed redirect to: ${finalUrl}`);

    for (const finding of result.findings) {
        const line = headerFindingLine(finding);
        if (finding.status === 'GOOD') logger.success(line);
        else if (finding.status === 'INFO' || finding.status === 'N/A') logger.info(line);
        else logger.warn(line);
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

            if (options.output) {
                writeHeaderGradeResult(options.output, { url, finalUrl, ...result });
            }
        } catch (err) {
            logger.error(`Header grading failed: ${err.message}`);
            process.exit(1);
        }
    });

program.parse(process.argv);
