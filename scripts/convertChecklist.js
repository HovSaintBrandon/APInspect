#!/usr/bin/env node
/**
 * scripts/convertChecklist.js
 *
 * One-off converter: reads an XLSX checklist (FALCON Review format) and outputs
 * src/config/checklist.json in the canonical APInspect schema.
 *
 * Usage:
 *   npm install xlsx          # install SheetJS once
 *   node scripts/convertChecklist.js <path-to-xlsx> [output-path]
 *
 * Expected XLSX columns (case-insensitive, first sheet):
 *   - "Subject" or "Category"  → maps to `category`
 *   - "Test Name" or "Test"    → maps to `test_name`
 *   - "ID" (optional)          → maps to `id`
 *
 * After running, manually review the output and fill in `maps_to_check` for
 * items where a hardcoded check module already exists.
 */

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Dependency check — xlsx must be installed separately (not in main deps)
// ---------------------------------------------------------------------------
let XLSX;
try {
    XLSX = require('xlsx');
} catch {
    console.error('[convertChecklist] ERROR: "xlsx" package is not installed.');
    console.error('  Run: npm install xlsx');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Existing checks registry — used to auto-fill maps_to_check where possible
// ---------------------------------------------------------------------------
const KNOWN_MAPPINGS = {
    'authentication': 'authentication/authRequired',
    'auth': 'authentication/authRequired',
    'sql':  'injection/sqliXss',
    'xss':  'injection/sqliXss',
    'injection': 'injection/sqliXss',
    'path traversal': 'injection/pathTraversal',
    'cors': 'misconfigurations/cors',
    'security header': 'misconfigurations/securityHeaders',
    'stack trace': 'errorHandling/stackTrace',
    'rate limit': 'rateLimiting/bruteForce',
    'brute force': 'rateLimiting/bruteForce',
    'endpoint discover': 'discovery/endpointDiscovery',
    'http method': 'discovery/httpMethods',
    'sensitive data': 'dataExposure/sensitiveData',
};

// Categories where no hardcoded check exists yet → always AI probe
const AI_PROBE_CATEGORIES = new Set([
    'mass assignment',
    'business logic',
    'websocket',
    'web socket',
    'third-party',
    'third party',
    'ci/cd',
    'cicd',
    'infrastructure',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const normaliseHeader = (h) => String(h || '').toLowerCase().trim();

const findColumn = (headers, ...candidates) => {
    const normalized = headers.map(normaliseHeader);
    for (const candidate of candidates) {
        const idx = normalized.indexOf(candidate.toLowerCase());
        if (idx !== -1) return idx;
    }
    return -1;
};

const slugId = (category, index) => {
    const prefix = (category || 'ITEM').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
    return `${prefix}-${String(index + 1).padStart(2, '0')}`;
};

const autoMapCheck = (testName, category) => {
    const haystack = `${testName} ${category}`.toLowerCase();
    for (const [keyword, modulePath] of Object.entries(KNOWN_MAPPINGS)) {
        if (haystack.includes(keyword)) return modulePath;
    }
    return null;
};

const isAiProbeCategory = (category) => {
    const lower = (category || '').toLowerCase();
    for (const cat of AI_PROBE_CATEGORIES) {
        if (lower.includes(cat)) return true;
    }
    return false;
};

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
const [,, inputFile, outputFile] = process.argv;

if (!inputFile) {
    console.error('Usage: node scripts/convertChecklist.js <path-to-xlsx> [output-path]');
    process.exit(1);
}

const absInput = path.resolve(inputFile);
if (!fs.existsSync(absInput)) {
    console.error(`File not found: ${absInput}`);
    process.exit(1);
}

console.log(`Reading: ${absInput}`);
const workbook = XLSX.readFile(absInput);
const sheetName = workbook.SheetNames[0];
console.log(`Using sheet: "${sheetName}"`);

const sheet = workbook.Sheets[sheetName];
const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });

if (rows.length < 2) {
    console.error('Sheet has no data rows.');
    process.exit(1);
}

const headers = rows[0];
const dataRows = rows.slice(1);

const idCol       = findColumn(headers, 'id', 'no', '#');
const categoryCol = findColumn(headers, 'subject', 'category', 'area');
const testNameCol = findColumn(headers, 'test name', 'test', 'description', 'check');

if (categoryCol === -1 || testNameCol === -1) {
    console.error('Could not locate required columns (Subject/Category, Test Name).');
    console.error(`Found headers: ${headers.join(', ')}`);
    process.exit(1);
}

// Group to assign sequential IDs per category
const categoryCounters = {};
const checklist = [];

for (const row of dataRows) {
    const category = String(row[categoryCol] || '').trim();
    const testName = String(row[testNameCol] || '').trim();

    // Skip empty rows
    if (!category && !testName) continue;

    categoryCounters[category] = (categoryCounters[category] || 0) + 1;
    const counter = categoryCounters[category];

    const rawId = idCol !== -1 ? String(row[idCol] || '').trim() : '';
    const id = rawId || slugId(category, counter - 1);

    const mapsToCheck = autoMapCheck(testName, category);
    const requiresAiProbe = mapsToCheck === null || isAiProbeCategory(category);

    checklist.push({
        id,
        category,
        test_name: testName,
        maps_to_check: requiresAiProbe ? null : mapsToCheck,
        requires_ai_probe: requiresAiProbe,
    });
}

const outPath = outputFile
    ? path.resolve(outputFile)
    : path.join(__dirname, '../src/config/checklist.json');

const outDir = path.dirname(outPath);
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

fs.writeFileSync(outPath, JSON.stringify(checklist, null, 2));
console.log(`\n✔ Wrote ${checklist.length} checklist items to: ${outPath}`);
console.log('\nNext steps:');
console.log('  1. Review checklist.json and verify auto-mapped checks (maps_to_check).');
console.log('  2. Manually set maps_to_check for items that match an existing module.');
console.log('  3. Commit checklist.json — treat it as a versioned spec, not generated output.');
