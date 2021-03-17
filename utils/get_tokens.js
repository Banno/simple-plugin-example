const fetch = require('node-fetch')
const jwt_decode = require('jwt-decode')
const querystring = require('querystring')

const get_tokens = async (base_url, clientId, clientSecret, auth_code, redirect_uri, codeVerifier) => {
    // Use the token endpoint we will use to exchange the code for a token
    const token_url = `${base_url}/a/consumer/api/v0/oidc/token`

    // Send a request to the token endpoint to receive the authenticated payload
    const auth_response = await fetch(token_url, {
        method: 'post',
        headers: { 
            'Content-Type': 'application/x-www-form-urlencoded'
        }, 
        body: `client_id=${clientId}&client_secret=${clientSecret}&grant_type=authorization_code&code=${auth_code}&redirect_uri=${redirect_uri}&code_verifier=${codeVerifier}`
    })

    // Parse and decode the response to get the appropriate tokens
    // First we want the access token which is needed to make authenticated API calls
    // Second we want the identity token so we can have more context about the user
    const token_response = await auth_response.text()
    const access_token = JSON.parse(token_response).access_token
    const id_token = JSON.parse(token_response).id_token
    const id_token_decoded = jwt_decode(id_token)

    return({
        access_token: access_token,
        id_token: id_token_decoded
    })
}

module.exports = get_tokens