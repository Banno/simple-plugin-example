const fetch = require('node-fetch')
const config = require('../config')
const exchangeAuthCode = require('../utils/tokenService')
const { createPkcePair } = require('../utils/pkce')
const { createState } = require('../utils/state')

// This example project doesn't include any storage mechanism (e.g. a database) for managing state.
// Therefore, we use this as our 'storage' for the purposes of this example.
// This method is NOT recommended for use in production systems.

const stateStore = new Map()

const initAuth = async (req, res) => {
    const redirectUri = `http://localhost:${config.app_port}/auth/callback`
    
    if (req.query.state) {
        stateStore.delete(req.query.state)
    }

    const { codeVerifier, codeChallenge } = createPkcePair()

    const state = createState()
    stateStore.set(state, codeVerifier)
    res.cookie(`STATE_${state}`, codeVerifier, { httpOnly: true, sameSite: 'lax' })

    const authBaseURL = `${config.api.environment}/a/consumer/api/v0/oidc/auth`
    const scopesParameterEncoded = `?scope=${encodeURIComponent('openid profile https://api.banno.com/consumer/auth/accounts.readonly')}`
    const responseTypeParameter = `&response_type=code`
    const clientIdParameter = `&client_id=${config.api.client_id}`
    const redirectUriParameterEncoded = `&redirect_uri=${encodeURIComponent(redirectUri)}`
    const stateParameter = `&state=${state}`

    const claims = {
        'https://api.banno.com/consumer/claim/institution_id': null,
        // If you uncomment this line for the 'Unique Customer Identifer' Restricted claim,
        // the administrator at the financial institution would also need to enable that restricted claim
        // for the External Application used by this example in order to actually receive data for that claim.
        //'https://api.banno.com/consumer/claim/customer_identifier': null,

    }

    const claimsToRequest = {
        id_token: claims,
        userinfo: claims,
    }

    const claimsParameterValue = encodeURIComponent(JSON.stringify(claimsToRequest))
    const claimsParameter = `&claims=${claimsParameterValue}`
    const codeChallengeParameter = `&code_challenge=${codeChallenge}`
    const codeChallengeMethodParameter = `&code_challenge_method=S256`

    const authorizationURL = `${authBaseURL}${scopesParameterEncoded}${responseTypeParameter}${clientIdParameter}${redirectUriParameterEncoded}${stateParameter}${codeChallengeParameter}${codeChallengeMethodParameter}${claimsParameter}`
    console.log(`Authorization URL: ${authorizationURL}`)

    res.redirect(authorizationURL)
}

const handleAuthCallback = async (req, res) => {
    const redirectUri = `http://localhost:${config.app_port}/auth/callback`
    if (!req.query.code || !req.query.state) {
        return res.status(400).send('Auth error: Missing code or state')
    }

    const state = req.query.state
    const codeVerifier = stateStore.get(state)
    stateStore.delete(state)

    if (!codeVerifier) {
        return res.status(400).send('Auth error: Invalid state')
    }

    const authCode = req.query.code

    const myTokens = await exchangeAuthCode(config.api.environment, config.api.client_id, config.api.client_secret, authCode, redirectUri, codeVerifier)
    const accessToken = myTokens.accessToken
    const idToken = myTokens.idToken

    console.log('Identity Token:')
    console.log(idToken)
    console.log(`Unique identifier for the institution: ${idToken['https://api.banno.com/consumer/claim/institution_id']}`)

    const userId = idToken.sub
    const userAccountsEndpoint = `${config.api.environment}/a/consumer/api/v0/users/${userId}/accounts`
    const userAccountsInfo = await fetch(userAccountsEndpoint, {
        method: 'get',
        headers: { 'Authorization': 'Bearer ' + accessToken }
    })

    const userAccountsString = await userAccountsInfo.text()
    const accountsData = JSON.parse(userAccountsString)

    res.render('pages/dynamic', {
        given_name: idToken.given_name,
        accounts_count: accountsData.accounts.length
    })
}

module.exports = {
    initAuth,
    handleAuthCallback
}