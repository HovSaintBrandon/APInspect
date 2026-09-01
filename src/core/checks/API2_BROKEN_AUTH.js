// API2:2023 Broken Authentication — wraps the existing deterministic
// auth-enforcement check (strips auth headers, confirms the endpoint rejects
// the unauthenticated request). Same logic as the legacy/checklist path's
// authentication/authRequired check, under its OWASP ID for the declarative path.
module.exports = require('../../checks/authentication/authRequired');
