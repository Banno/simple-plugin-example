const crypto = require('crypto');

function createState() {
    return crypto.randomBytes(60).toString('hex').slice(0, 128);
}

module.exports = {
    createState
}
