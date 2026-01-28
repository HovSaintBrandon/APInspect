#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const { parse, parseRaw } = require('../core/parser');
const Engine = require('../core/engine');
const jsonReporter = require('../reporters/jsonReporter');
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
            newmanRunner.runAudit(file, options.env);
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
    .option('-o, --output <path>', 'Path to save JSON report')
    .action(async (file, options) => {
        try {
            logger.title('Initializing APInspect...');

            // 1. Parse Input
            const config = await parse(file);

            // 2. Apply API Token override if provided
            if (options.token) {
                config.auth = { type: 'bearer', token: options.token };
                logger.info('Using provided bearer token.');
            } else if (options.username && options.password) {
                config.auth = { type: 'basic', username: options.username, password: options.password };
                logger.info('Using provided Basic Auth credentials.');
            }

            // 3. Initialize Engine
            const engine = new Engine(config);
            engine.loadChecks(); // Default checks

            // 4. Run Scan
            const results = await engine.run();

            // 5. Generate Report
            if (options.output && options.output.endsWith('.csv')) {
                const csvReporter = require('../reporters/csvReporter');
                csvReporter.generate(results, options.output);
            } else {
                // Default to JSON
                jsonReporter.generate(results, options.output);
            }

        } catch (err) {
            logger.error(`Scan failed: ${err.message}`);
            process.exit(1);
        }
    });

program.parse(process.argv);
