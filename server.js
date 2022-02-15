/*
 * Copyright 2020 Jack Henry & Associates, Inc.®
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const express = require('express')
const app = express()
const fetch = require('node-fetch')
const crypto = require('crypto')

const config = require('./config')
const get_tokens = require('./utils/get_tokens')
const { createCodeVerifier } = require('./utils/pkce')

// set the view engine to ejs
app.set('view engine', 'ejs')

// First plugin, renders static HTML
app.get('/static', (req, res) => {
    res.render('pages/static')
})

// This example project doesn't include any storage mechanism (e.g. a database) for managing state.
// Therefore, we use this as our 'storage' for the purposes of this example.
// This method is NOT recommended for use in production systems.
const stateStore = new Map()

// Final plugin, renders dynamic HTML
app.get('/dynamic', async (req, res) => {
    // The REDIRECT_URI must be added to the External Application settings in Banno People.
    // *NOTE* it is case sensitive.
    // See more details at https://jackhenry.dev/open-api-docs/plugins/architecture/ExternalApplications/
    const REDIRECT_URI = `http://localhost:${config.app_port}/dynamic`

    let state
    let codeVerifier
    if (!req.query.code || !req.query.state) {
        // If we are in this state, then we are starting a new authorization flow.
        if (req.query.state) {
            stateStore.delete(req.query.state)
        }

        // PKCE (Proof Key for Code Exchange) is an OAuth extension that adds additional security to the Authorization Code flow.
        // Here we create both the Code Verifier and Code Challenge.
        // See more details at https://tools.ietf.org/html/rfc7636
        codeVerifier = createCodeVerifier(codeVerifier)
        const CODE_CHALLENGE = crypto.createHash('sha256')
            .update(Buffer.from(codeVerifier)).digest('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')

        // We save the Code Verifier for later use in the authorization flow.
        state = crypto.randomBytes(60).toString('hex').slice(0, 128)
        stateStore.set(state, codeVerifier)
        res.cookie(`STATE_${state}`, codeVerifier, {httpOnly: true, sameSite: 'lax'})

        // Build up the authorization URL piece by piece, starting with the authorization endpoint.
        const authBaseURL = `${config.api.environment}/a/consumer/api/v0/oidc/auth`

        // See more about scopes (and claims) at https://jackhenry.dev/open-api-docs/authentication-framework/overview/OpenIDConnectOAuth/
        const scopesParameterEncoded = `?scope=${encodeURIComponent('openid profile https://api.banno.com/consumer/auth/accounts.readonly')}`

        const responseTypeParameter = `&response_type=code`
       
        const clientIdParameter = `&client_id=${config.api.client_id}`
       
        const redirectUriParameterEncoded = `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
       
        const stateParameter = `&state=${state}`

        // Here we pass along the Code Challenge and method to the authorization server.
        const codeChallengeParameter = `&code_challenge=${CODE_CHALLENGE}`
        const codeChallengeMethodParameter = `&code_challenge_method=S256`

        let authorizationURL = `${authBaseURL}${scopesParameterEncoded}${responseTypeParameter}${clientIdParameter}${redirectUriParameterEncoded}${stateParameter}${codeChallengeParameter}${codeChallengeMethodParameter}`

        // Redirect to begin the authorization flow.
        res.redirect(authorizationURL)
        return
    } else {
        // Retrieve the Code Verifier from the stored state.
        state = req.query.state
        codeVerifier = stateStore.get(state)
        stateStore.delete(state)
    }

    // Get the Authorization Code from the redirect URL parameters
    const auth_code = req.query.code

    // Here we pass along the Code Verifier to the authorization server as part of the
    // flow to exchange an Authorization Code for an Access Token and Identity Token.
    //
    // As part of PKCE, the Code Verifier is what the authorization server uses to verify
    // that the application requesting to exchange an Authorization Code for an Access Token and Identity Token
    // is the same application which began the authorization flow.
    const my_tokens = await get_tokens(config.api.environment, config.api.client_id, config.api.client_secret, auth_code, REDIRECT_URI, codeVerifier)
    const access_token = my_tokens.access_token
    const id_token = my_tokens.id_token

    // We can access some user information from the decoded Identity Token.
    // The "sub" OpenID Connect claim is the unique subject identifier for the user.
    // This value can be used where API calls use the placeholder {userId} in API path definitions.
    // See more details at https://jackhenry.dev/open-api-docs/authentication-framework/overview/OpenIDConnectOAuth/
    const user_id = id_token.sub

    // We can use the Access Token to gain authorized access to the user's resources.
    const user_accounts_endpoint = `${config.api.environment}/a/consumer/api/v0/users/${user_id}/accounts`
    const user_accounts_info = await fetch(user_accounts_endpoint, {
        method: 'get',
        headers: { 'Authorization': 'Bearer ' + access_token }
    })

    const user_accounts_string = await user_accounts_info.text()
    const accounts_data = JSON.parse(user_accounts_string)
    
    res.render('pages/dynamic', {
        given_name: id_token.given_name, 
        accounts_count: accounts_data.accounts.length
    })
})

app.listen(config.app_port, () => {
    console.log(`App running at http://localhost:${config.app_port}`)
})