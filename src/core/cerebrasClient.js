const axios = require('axios');
const logger = require('../utils/logger');
const { AI_MODEL } = require('../config/aiConfig');

const CEREBRAS_URL = 'https://api.cerebras.ai/v1/chat/completions';

async function scoreCheck({ model = AI_MODEL, systemPrompt, evidence }) {
    if (!process.env.CEREBRAS_API_KEY) {
        logger.warn('CEREBRAS_API_KEY environment variable is missing.');
        return { status: 'MANUAL', message: 'Missing Cerebras API Key — flagged for manual review' };
    }

    try {
        const res = await axios.post(CEREBRAS_URL, {
            model,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: JSON.stringify(evidence) }
            ],
            response_format: { type: 'json_object' },
            temperature: 0
        }, {
            headers: { Authorization: `Bearer ${process.env.CEREBRAS_API_KEY}` }
        });

        const parsed = JSON.parse(res.data.choices[0].message.content);
        
        // Ensure the model returned the required fields
        if (!parsed.verdict || !parsed.evidence_cited) {
            return { status: 'MANUAL', message: 'AI response malformed — flagged for manual review' };
        }
        
        return parsed;
    } catch (err) {
        logger.error(`Cerebras API call failed: ${err.message}`);
        return { status: 'MANUAL', message: `AI request failed: ${err.message}` };
    }
}

module.exports = { scoreCheck };
