const crypto = require('crypto');

// PKCE (Proof Key for Code Exchange) is an OAuth extension that adds additional security to the Authorization Code flow.
// Here we create the Code Verifier.
// See more details at https://tools.ietf.org/html/rfc7636
function createCodeVerifier(codeVerifier) {
    codeVerifier = crypto.randomBytes(60).toString('hex').slice(0, 128);
    return codeVerifier;
}

// PKCE (Proof Key for Code Exchange) is an OAuth extension that adds additional security to the Authorization Code flow.
// Here we create the Code Challenge.
// See more details at https://tools.ietf.org/html/rfc7636
function createCodeChallenge(codeVerifier) {
    return crypto.createHash('sha256')
        .update(Buffer.from(codeVerifier)).digest('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
}

module.exports = {
    createCodeVerifier,
    createCodeChallenge
}
