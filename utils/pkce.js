const crypto = require('crypto');

// PKCE (Proof Key for Code Exchange) is an OAuth extension that adds additional security to the Authorization Code flow.
// Here we create the Code Verifier.
// See more details at https://tools.ietf.org/html/rfc7636
function createCodeVerifier(codeVerifier) {
    codeVerifier = crypto.randomBytes(60).toString('hex').slice(0, 128);
    return codeVerifier;
}

module.exports = {
    createCodeVerifier
}
