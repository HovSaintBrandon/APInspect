// API4:2023 Unrestricted Resource Consumption — wraps the existing deterministic
// rate-limiting/brute-force check (fires parallel requests, checks for 429).
module.exports = require('../../checks/rateLimiting/bruteForce');
