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
    // The REDIRECT_URI must be added to the institution settings in Banno People.
    // *NOTE* it is case sensitive
    // See more details at https://jackhenry.dev/open-api-docs/plugins/architecture/ExternalApplications/
    const REDIRECT_URI = `http://localhost:${config.app_port}/dynamic`

    let state
    let codeVerifier
    if (!req.query.code || !req.query.state) {
        if (req.query.state) {
            stateStore.delete(req.query.state)
        }

        // create the PKCE code verifier and stash it for later
        codeVerifier = crypto.randomBytes(60).toString('hex').slice(0, 128)
        const CODE_CHALLENGE = crypto.createHash('sha256')
            .update(Buffer.from(codeVerifier)).digest('base64')
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')

        state = crypto.randomBytes(60).toString('hex').slice(0, 128)
        stateStore.set(state, codeVerifier)
        res.cookie(`STATE_${state}`, codeVerifier, {httpOnly: true, sameSite: 'lax'})

        // redirect
        res.redirect(`${config.api.environment}/a/consumer/api/v0/oidc/auth?scope=${encodeURIComponent('openid profile https://api.banno.com/consumer/auth/accounts.readonly')}&response_type=code&client_id=${config.api.client_id}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256`)
        return
    } else {
        state = req.query.state
        codeVerifier = stateStore.get(state)
        stateStore.delete(state)
    }

    // Get the Authorization Code from the URL parameters
    const auth_code = req.query.code

    // Use the get_tokens helper function to receive the authenticated payload
    const my_tokens = await get_tokens(config.api.environment, config.api.client_id, config.api.client_secret, auth_code, REDIRECT_URI, codeVerifier)
    const access_token = my_tokens.access_token
    const id_token = my_tokens.id_token

    // We can access some user information from the decoded Identity Token.
    // The "sub" OpenID Connect claim is the unique subject identifier for the user.
    // This value can be used where API calls use the placeholder {userId} in API path definitions.
    // See more details at https://jackhenry.dev/open-api-docs/authentication-framework/overview/OpenIDConnectOAuth/
    const user_id = id_token.sub

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