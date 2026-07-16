const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const logger = require('../src/utils/logger');

// Severity-ordered for threshold comparison
const SEVERITY_ORDER = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4 };

function spawnScan(args) {
    return new Promise((resolve) => {
        const scan = spawn('node', args);
        scan.stdout.on('data', d => process.stdout.write(d.toString()));
        scan.stderr.on('data', d => process.stderr.write(d.toString()));
        // Always resolve — non-zero exit is expected when --fail-on triggers
        scan.on('close', code => resolve(code));
    });
}

async function runEval() {
    logger.title('Starting APInspect Eval Harness');

    // Start Mock Server
    const serverPath = path.join(__dirname, 'mock-server', 'server.js');
    const serverProcess = spawn('node', [serverPath]);

    serverProcess.stdout.on('data', d => console.log(`[Mock Server] ${d.toString().trim()}`));
    serverProcess.stderr.on('data', d => console.error(`[Mock Server] ${d.toString().trim()}`));

    // Give it a second to start
    await new Promise(r => setTimeout(r, 1500));

    const configPath = path.join(__dirname, 'temp-config.json');
    try {
        const groundTruth = require('./ground-truth/mock-api.json');

        // Write a temporary config for the scan
        fs.writeFileSync(configPath, JSON.stringify({
            base_url: groundTruth.base_url,
            endpoints: groundTruth.cases.map(c => ({ path: c.endpoint, methods: [c.method] }))
        }));

        // ---------------------------------------------------------------
        // Phase 1: Majority-vote correctness eval (3 passes)
        // ---------------------------------------------------------------
        logger.info('Running scan passes (Majority vote over 3 runs due to temp 0.1 drift)...');

        const allResults = [];
        for (let i = 0; i < 3; i++) {
            logger.info(`\n--- Pass ${i + 1} ---`);
            const outPath = path.join(__dirname, `results-${i}.json`);

            const exitCode = await spawnScan([
                path.join(__dirname, '../src/cli/index.js'),
                'scan', configPath,
                '--checklist',
                '-o', outPath
            ]);

            logger.info(`Pass ${i + 1} exited with code ${exitCode}`);

            if (fs.existsSync(outPath)) {
                // Clear require cache so we get fresh data each run
                delete require.cache[require.resolve(outPath)];
                allResults.push(require(outPath));
            } else {
                logger.warn(`Run ${i + 1} failed to produce output json.`);
            }
        }

        // Majority Vote Eval
        logger.title('\n--- Eval Results ---');
        let falseNegatives = 0;
        let falsePositives = 0;
        let tbcCount = 0;

        for (const expectedCase of groundTruth.cases) {
            const verdicts = [];
            for (const runData of allResults) {
                const runResults = runData.results || [];
                const match = runResults.find(r => r.endpoint === expectedCase.endpoint && r.check === `checklist/${expectedCase.check_id}`);
                const matchHardcoded = runResults.find(r => r.endpoint === expectedCase.endpoint && r.check === expectedCase.check_id);

                if (match) verdicts.push(match.status);
                else if (matchHardcoded) verdicts.push(matchHardcoded.status);
                else verdicts.push('N/A');
            }

            // Majority logic
            const counts = {};
            for (const v of verdicts) counts[v] = (counts[v] || 0) + 1;
            let majorityVerdict = verdicts[0] || 'N/A';
            let maxCount = 0;
            for (const [v, c] of Object.entries(counts)) {
                if (c > maxCount) { maxCount = c; majorityVerdict = v; }
            }

            const expected = expectedCase.expected_verdict;
            let outcome = "MATCH";

            if (majorityVerdict === 'TO BE CONFIRMED' || majorityVerdict === 'MANUAL') {
                tbcCount++;
                outcome = "TBC";
            } else if (majorityVerdict === 'PASS' && expected === 'FAILED') {
                falseNegatives++;
                outcome = "FALSE NEGATIVE";
            } else if (majorityVerdict === 'FAILED' && expected === 'PASS') {
                falsePositives++;
                outcome = "FALSE POSITIVE";
            }

            logger.info(`[${outcome}] ${expectedCase.check_id} on ${expectedCase.endpoint} -> Expected: ${expected}, Got: ${majorityVerdict} (Votes: ${verdicts.join(', ')})`);
        }

        logger.info(`\nMetrics: False Negatives: ${falseNegatives}, False Positives: ${falsePositives}, TBC Rate: ${tbcCount}/${groundTruth.cases.length}`);

        // ---------------------------------------------------------------
        // Phase 2: --fail-on exit code contract tests
        // ---------------------------------------------------------------
        logger.title('\n--- Exit Code Contract Tests ---');

        // Test 1: --fail-on high should exit 1 (mock server has DATA-01 = High severity FAIL)
        const exitCodeFailOnHigh = await spawnScan([
            path.join(__dirname, '../src/cli/index.js'),
            'scan', configPath,
            '--checklist',
            '--fail-on', 'high',
            '-o', path.join(__dirname, 'results-failon.json')
        ]);
        const test1Pass = exitCodeFailOnHigh === 1;
        logger.info(`[${test1Pass ? 'PASS' : 'FAIL'}] --fail-on high → exit ${exitCodeFailOnHigh} (expected 1)`);

        // Test 2: --fail-on-tbc without --fail-on should exit 2 (validation error)
        const exitCodeTbcAlone = await spawnScan([
            path.join(__dirname, '../src/cli/index.js'),
            'scan', configPath,
            '--checklist',
            '--fail-on-tbc'
        ]);
        const test2Pass = exitCodeTbcAlone === 2;
        logger.info(`[${test2Pass ? 'PASS' : 'FAIL'}] --fail-on-tbc alone → exit ${exitCodeTbcAlone} (expected 2)`);

        // Test 3: --fail-on critical should exit 0 (AUTH-01 is Critical but TBC — excluded without --fail-on-tbc)
        const exitCodeFailOnCritical = await spawnScan([
            path.join(__dirname, '../src/cli/index.js'),
            'scan', configPath,
            '--checklist',
            '--fail-on', 'critical',
            '-o', path.join(__dirname, 'results-failon-crit.json')
        ]);
        const test3Pass = exitCodeFailOnCritical === 0;
        logger.info(`[${test3Pass ? 'PASS' : 'FAIL'}] --fail-on critical → exit ${exitCodeFailOnCritical} (expected 0)`);

        // Test 4: --fail-on critical --fail-on-tbc should exit 1 (AUTH-01 is a Critical MANUAL finding)
        const exitCodeFailOnCriticalTbc = await spawnScan([
            path.join(__dirname, '../src/cli/index.js'),
            'scan', configPath,
            '--checklist',
            '--fail-on', 'critical',
            '--fail-on-tbc',
            '-o', path.join(__dirname, 'results-failon-crit-tbc.json')
        ]);
        const test4Pass = exitCodeFailOnCriticalTbc === 1;
        logger.info(`[${test4Pass ? 'PASS' : 'FAIL'}] --fail-on critical --fail-on-tbc → exit ${exitCodeFailOnCriticalTbc} (expected 1)`);

        logger.info(`\nExit Code Tests: ${[test1Pass, test2Pass, test3Pass, test4Pass].filter(Boolean).length}/4 passed`);

        // Cleanup result files
        for (const f of ['results-0.json', 'results-1.json', 'results-2.json', 'results-failon.json', 'results-failon-crit.json', 'results-failon-crit-tbc.json']) {
            const p = path.join(__dirname, f);
            if (fs.existsSync(p)) fs.unlinkSync(p);
        }

    } finally {
        if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
        serverProcess.kill();
    }
}

runEval().catch(e => {
    logger.error(e);
    process.exit(1);
});
