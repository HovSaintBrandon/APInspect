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
    .description('Scan an API definition file (JSON)')
    .option('-t, --token <token>', 'Bearer token for authentication')
    .option('-u, --username <user>', 'Username for Basic Auth')
    .option('-p, --password <pass>', 'Password for Basic Auth')
    .option('-b, --base-url <url>', 'Base URL to use for the scan')
    .option('--auth-file <path>', 'Path to JSON file containing role:token mapping or login_endpoint config')
    .option('-o, --output <path>', 'Path to save report (.json, .csv, or .falcon.csv)')
    .option('--checklist', 'Run in checklist-driven mode using src/config/checklist.json + AI layer')
    .option('--fail-on <severity>', 'Fail with exit code 1 if any confirmed finding meets or exceeds this severity (critical, high, medium, low, info)')
    .option('--fail-on-tbc', 'Also fail on TO BE CONFIRMED findings that meet --fail-on severity (requires --fail-on)')
    .action(async (file, options) => {
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

            // Collect all results across roles for exit-code evaluation
            const allResults = [];

            // 1. Parse Input
            const config = await parse(file, options.baseUrl);

            // 2. Auth handling
            let authMap = {};
            if (options.authFile) {
                const absPath = require('path').resolve(options.authFile);
                if (!require('fs').existsSync(absPath)) {
                    throw new Error(`Auth file not found: ${options.authFile}`);
                }
                const authConfig = require(absPath);
                
                if (authConfig.login_endpoint && authConfig.roles) {
                    logger.info(`Fetching dynamic tokens from ${authConfig.login_endpoint}...`);
                    const axios = require('axios');
                    
                    for (const role of authConfig.roles) {
                        try {
                            const res = await axios({
                                method: authConfig.method || 'POST',
                                url: authConfig.login_endpoint,
                                data: role.payload,
                                headers: { 'Content-Type': 'application/json' }
                            });
                            
                            const pathParts = (authConfig.token_path || 'token').split('.');
                            let token = res.data;
                            for (const part of pathParts) {
                                if (token) token = token[part];
                            }
                            
                            if (token) {
                                authMap[role.name] = { type: 'bearer', token };
                                logger.info(`✅ Successfully fetched token for role: ${role.name}`);
                            } else {
                                logger.error(`❌ Token path '${authConfig.token_path}' not found in response for ${role.name}`);
                            }
                        } catch (err) {
                            logger.error(`❌ Failed to fetch token for role ${role.name}: ${err.message}`);
                        }
                    }
                } else if (Array.isArray(authConfig.roles)) {
                    // Per-role schema: each role declares its own auth_type
                    // Supports 'bearer' (dynamic JWT fetch) and 'basic' (pre-encoded header)
                    logger.info(`Processing ${authConfig.roles.length} roles from auth file...`);
                    const axios = require('axios');

                    for (const role of authConfig.roles) {
                        if (role.auth_type === 'basic') {
                            // Build Basic Auth header directly from credentials — no login endpoint needed
                            const encoded = Buffer.from(
                                `${role.credentials.username}:${role.credentials.password}`
                            ).toString('base64');
                            authMap[role.name] = {
                                type: 'basic',
                                header: `Basic ${encoded}`,
                                username: role.credentials.username,
                                password: role.credentials.password
                            };
                            logger.info(`🔑 Loaded Basic Auth for role: ${role.name} (user: ${role.credentials.username})`);

                        } else if (role.auth_type === 'bearer') {
                            // Dynamically fetch a JWT from the role's own login_endpoint
                            try {
                                const res = await axios({
                                    method: role.method || 'POST',
                                    url: role.login_endpoint,
                                    data: role.payload,
                                    headers: { 'Content-Type': 'application/json' }
                                });

                                const pathParts = (role.token_path || 'token').split('.');
                                let token = res.data;
                                for (const part of pathParts) {
                                    if (token) token = token[part];
                                }

                                if (token) {
                                    authMap[role.name] = { type: 'bearer', token };
                                    logger.info(`✅ Fetched Bearer token for role: ${role.name}`);
                                } else {
                                    logger.error(`❌ token_path '${role.token_path}' not found in response for ${role.name}`);
                                }
                            } catch (err) {
                                logger.error(`❌ Failed to fetch token for role ${role.name}: ${err.message}`);
                            }
                        } else {
                            logger.warn(`⚠ Unknown auth_type '${role.auth_type}' for role ${role.name} — skipping.`);
                        }
                    }
                } else {
                    // Legacy flat mapping format fallback
                    authMap = authConfig;
                    logger.info(`Loaded auth map with ${Object.keys(authMap).length} roles.`);
                }
            } else if (options.token) {
                authMap = { default: { type: 'bearer', token: options.token } };
                logger.info('Using provided bearer token.');
            } else if (options.username && options.password) {
                authMap = { default: { type: 'basic', username: options.username, password: options.password } };
                logger.info('Using provided Basic Auth credentials.');
            } else {
                authMap = { unauthenticated: null };
            }

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
            logger.error(`Scan failed: ${err.message}`);
            process.exit(1);
        }
    });

program.parse(process.argv);
