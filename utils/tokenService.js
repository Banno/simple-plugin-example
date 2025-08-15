
const fetch = require('node-fetch')
const jwt_decode = require('jwt-decode')
const querystring = require('querystring')

const exchangeAuthCode = async (baseUrl, clientId, clientSecret, authCode, redirectUri, codeVerifier) => {
    const tokenUrl = `${baseUrl}/a/consumer/api/v0/oidc/token`

    const authResponse = await fetch(tokenUrl, {
        method: 'post',
        headers: { 
            'Content-Type': 'application/x-www-form-urlencoded'
        }, 
        body: `client_id=${clientId}&client_secret=${clientSecret}&grant_type=authorization_code&code=${authCode}&redirect_uri=${redirectUri}&code_verifier=${codeVerifier}`
    })

    const tokenResponse = await authResponse.text()
    const accessToken = JSON.parse(tokenResponse).access_token
    const idToken = JSON.parse(tokenResponse).id_token
    const idTokenDecoded = jwt_decode(idToken)

    return {
        accessToken: accessToken,
        idToken: idTokenDecoded
    }
}

module.exports = exchangeAuthCode
