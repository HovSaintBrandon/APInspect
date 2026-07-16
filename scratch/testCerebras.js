/**
 * Standalone test for cerebrasClient.js
 * Run with: CEREBRAS_API_KEY=your_key node scratch/testCerebras.js
 */

const { scoreCheck } = require('../src/core/cerebrasClient');
const SYSTEM_PROMPT = require('../src/checks/dataExposure/prompts/sensitiveDataExposure');

const fakeEvidence = {
    url: 'https://api.example.com/api/users/1',
    method: 'GET',
    statusCode: 200,
    responseHeaders: [{ key: 'Content-Type', value: 'application/json' }],
    // Fake a response with a leaked token — should trigger FAIL
    responseBody: JSON.stringify({
        id: 1,
        email: 'alice@example.com',
        api_key: 'sk_live_abc123XYZ456',
        ssn: '123-45-6789',
    }),
};

(async () => {
    console.log('Sending evidence to Cerebras...\n');
    const result = await scoreCheck({ systemPrompt: SYSTEM_PROMPT, evidence: fakeEvidence });
    console.log('Result:\n', JSON.stringify(result, null, 2));
})();
