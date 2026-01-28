const newman = require('newman');
const path = require('path');
const logger = require('../utils/logger');

const DANGEROUS_STRINGS = [
    // Stack traces & debug patterns
    'at ',                  // common in JS/Python/Java/C# traces
    'Stack trace:',
    'Traceback (most recent call last)',
    'File "',
    'line ',
    '.java:',
    '.py:',
    'Error: ',
    'Exception in thread ',
    'Caused by: ',
    // Common debug/internal leaks
    'DEBUG',
    // 'console.log', // Too common in JS code snippets returned in HTML
    'process.env',
    'NODE_ENV',
    '/home/',
    '/var/www/',
    '/app/',
    'C:\\',
    'Internal Server Error', // sometimes paired with leaks
    // Sensitive data regexes (very basic – extend with better patterns)
    /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/, // JWTs
    /sk_live_|sk_test_|pk_live_|pk_test_/,               // Stripe
    /AKIA[0-9A-Z]{16}/,                                   // AWS keys (partial)
    /[A-Za-z0-9+/=]{40}/,                                 // possible tokens
    /\b\d{3}-\d{2}-\d{4}\b/,                              // SSN (US)
    /\b\d{16}\b/                                          // credit card (naive)
];

const extractSnippet = (text, keyword) => {
    // If regex match
    if (typeof keyword !== 'string') {
        return keyword.toString(); // simplified
    }
    const idx = text.toLowerCase().indexOf(keyword.toLowerCase());
    if (idx === -1) return '';
    const start = Math.max(0, idx - 40);
    return text.substring(start, start + 120) + '...';
};

const runAudit = (collectionPath, environmentPath) => {
    logger.title('Starting Newman-based Response Audit...');

    // Resolve paths
    const absCollectionPath = path.resolve(collectionPath);
    const absEnvPath = environmentPath ? path.resolve(environmentPath) : undefined;

    const findings = {
        stackTraces: [],
        debugInfo: [],
        sensitiveData: [],
        httpNotSecure: []
    };

    newman.run({
        collection: require(absCollectionPath),
        environment: absEnvPath ? require(absEnvPath) : undefined,
        reporters: 'cli',
        ignoreRedirects: true // Optional
    }, (err) => {
        if (err) {
            logger.error(`Newman run failed: ${err.message}`);
            // Don't exit, print findings anyway
        }
        printFindings(findings);
    }).on('request', (err, args) => {
        if (err) return;

        const response = args.response;
        const req = args.item.request;
        const name = args.item.name || 'unnamed';
        const url = req.url.toString();
        const method = req.method || 'GET';

        if (!response) return;

        const status = response.code;
        // response.text() or response.stream.toString() depending on version
        // args.response.stream is a Buffer
        const body = response.stream ? response.stream.toString() : '';

        // 1. Check for insecure transport
        if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
            // Avoid flagging localhost
            findings.httpNotSecure.push({ name, method, url, issue: 'Cleartext HTTP – sensitive data can be intercepted' });
        }

        // 3. Error/debug/stack trace scanning
        const lowerBody = body.toLowerCase();

        DANGEROUS_STRINGS.forEach(pattern => {
            let match;
            if (typeof pattern === 'string') {
                if (lowerBody.includes(pattern.toLowerCase())) {
                    // Filter out some common false positives if necessary
                    findings.debugInfo.push({ name, method, url, status, pattern, snippet: extractSnippet(body, pattern) });
                }
            } else if ((match = body.match(pattern))) {
                findings.sensitiveData.push({ name, method, url, status, type: 'possible-sensitive', match: match[0] });
            }
        });

        // Special case: looks like stack trace (multiple 'at ' lines or similar)
        if ((body.match(/at /g) || []).length >= 3) {
            findings.stackTraces.push({ name, method, url, status, snippet: body.substring(0, 300) + '...' });
        }
    });
};

const printFindings = (findings) => {
    logger.title('=== Response Security Audit Findings ===');

    if (findings.stackTraces.length > 0) {
        logger.error(`🚨 Possible stack traces leaked (${findings.stackTraces.length}):`);
        findings.stackTraces.forEach(f => logger.info(`  • ${f.method} ${f.url} (${f.status}) → ${f.name}`));
    }

    if (findings.debugInfo.length > 0) {
        logger.warn(`⚠️ Debug/internal info patterns (${findings.debugInfo.length}):`);
        findings.debugInfo.forEach(f => logger.info(`  • ${f.method} ${f.url} → "${f.pattern}"`));
    }

    if (findings.sensitiveData.length > 0) {
        logger.error(`🔥 Potential sensitive data exposure (${findings.sensitiveData.length}):`);
        findings.sensitiveData.forEach(f => logger.info(`  • ${f.method} ${f.url} → ${f.match}`));
    }

    if (findings.httpNotSecure.length > 0) {
        logger.warn(`⚠️ Insecure transport (http://) (${findings.httpNotSecure.length}):`);
        findings.httpNotSecure.forEach(f => logger.info(`  • ${f.url}`));
    }

    const total = Object.values(findings).flat().length;
    if (total === 0) {
        logger.success('No obvious security leaks found in responses.');
    } else {
        logger.info(`Total issues found: ${total}`);
    }
};

module.exports = { runAudit };
