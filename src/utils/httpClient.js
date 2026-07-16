const axios = require('axios');
const logger = require('./logger');

const createClient = (baseURL, headers = {}, timeout = 5000, context = null) => {
    const instance = axios.create({
        baseURL,
        timeout,
        headers,
        validateStatus: () => true // Don't throw on error status codes
    });

    // Automatically resolve {{variables}} in the URL before request is sent
    instance.interceptors.request.use(req => {
        if (context && req.url) {
            req.url = context.resolveString(req.url);
            
            // Also resolve variables inside the JSON body (if present)
            if (req.data && typeof req.data === 'string') {
                try {
                    req.data = JSON.parse(context.resolveString(req.data));
                } catch(e) {
                    req.data = context.resolveString(req.data);
                }
            } else if (req.data && typeof req.data === 'object') {
                const strData = JSON.stringify(req.data);
                req.data = JSON.parse(context.resolveString(strData));
            }
        }
        return req;
    });

    return instance;
};

module.exports = { createClient };
