const axios = require('axios');
const logger = require('./logger');

const createClient = (baseURL, headers = {}, timeout = 5000) => {
    const instance = axios.create({
        baseURL,
        timeout,
        headers,
        validateStatus: () => true // Don't throw on error status codes
    });

    // Request interceptor for logging (optional, can be verbose)
    // instance.interceptors.request.use(req => {
    //   return req;
    // });

    return instance;
};

module.exports = { createClient };
