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

const config = require('./config')
const get_tokens = require('./utils/get_tokens')

// set the view engine to ejs
app.set('view engine', 'ejs')

// Test plugin, renders static HTML
app.get('/static', (req, res) => {
    res.render('pages/static')
})

// Final plugin, renders dynamic HTML
app.get('/dynamic', async (req, res) => {
    // Get the authorization code from the URL parameters
    const auth_code = req.query.code

    const api_keys = `${config.api.client_id}:${config.api.client_secret}`
    const base64_keys = Buffer.from(api_keys).toString('base64')

    // The REDIRECT_URI must be added to the institution settings in Banno People
    // *NOTE* it is case sensitive
    const REDIRECT_URI = `http://localhost:${config.app_port}/dynamic`

    // Use the get_tokens helper function to receive the authenticated payload
    const my_tokens = await get_tokens(config.api.environment, base64_keys, auth_code, REDIRECT_URI)
    const access_token = my_tokens.access_token
    const id_token = my_tokens.id_token

    // We can access some user information from the decoded token
    const user_id = id_token.sub

    const user_accounts_endpoint = `${config.api.environment}/a/consumer/api/v0/users/${user_id}/accounts`
    const user_accounts_info = await fetch(user_accounts_endpoint, {
        method: 'get',
        headers: { 'Authorization': 'Bearer ' + access_token }
    })

    const user_accounts_string = await user_accounts_info.text()
    const accounts_data = JSON.parse(user_accounts_string)
    
    res.render('pages/dynamic', {
        account_name: id_token.given_name, 
        accounts_count: accounts_data.accounts.length
    })
})

app.listen(config.app_port, () => {
    console.log(`App running at http://localhost:${config.app_port}`)
})