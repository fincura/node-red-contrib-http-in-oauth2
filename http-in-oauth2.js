//   Copyright 2021 Fincura, Inc.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.


const { AuthorizationCode } = require('simple-oauth2');
const axios = require('axios');
const { default: jwtVerify } = require('jose/jwt/verify')
const { default: parseJwk } = require('jose/jwk/parse')
const { default: decodeProtectedHeader } = require('jose/util/decode_protected_header')

function base64Encode(str) {
    buff = Buffer.from(str, 'utf-8')
    return buff.toString('base64')
}

function base64Decode(str) {
    buff = Buffer.from(str, 'base64')
    return buff.toString('utf-8')
}

// a simple but effective auditing function to track important events
// in the future the console log call here should be updated to something more
// robust, but this will do for now.
function audit_event(user, action, detail) {
    if (typeof(detail) === "undefined") {
        console.log("http-in-oauth2 audit: ", `user:${user}`, action);
    } else {
        console.log("http-in-oauth2 audit: ", `user:${user}`, action, detail);
    }
}


module.exports = function(RED) {
    "use strict";
    function HttpInOauth2(config) {
        RED.nodes.createNode(this, config);
        let node = this;

        // insert defaults if optional settings are not specified
        if (config["auth-token-path"] === '') {
            config["auth-token-path"] = '/oauth2/token'
        }
        if (config["auth-authorize-path"] === '') {
            config["auth-authorize-path"] = '/oauth2/authorize'
        }
        if ( config["auth-cookie-name"] === '') {
            config["auth-cookie-name"] = 'oauth_id'
        }

        const oauth2_endpoint = config["auth-endpoint"]      // the OAuth2 host (start with https://, only include host name, no paths)
        const oauth2_authorize_path = config["auth-authorize-path"]  // the path to authorize from the host e.g.  /oauth2/authorize
        const oauth2_token_path = config["auth-token-path"]  // the path to the token api endpoint e.g. /oauth2/token
        const oauth2_scopes = config["auth-scopes"]          // the scopes to request from the OAuth2 host
        const oauth2_app_id = config["auth-app-id"]          // the application/client ID to use when talking to the oauth server
        const oauth2_app_secret = config["auth-app-secret"]  // the app/client secret to use when calling the token endpoint
        const oauth2_jwks_url = config["auth-jwks-url"]      // a url containing the public keys used to sign the JWTs
        const app_callback_host = config["callback-host"]    // the node red server 
        const app_callback_path = config["callback-path"]    // the callback path. we'll listen on that and do redirects when auth is missing
        const app_cookie_name = config["auth-cookie-name"]   // the name of the cookie we'll store the OAuth ID token in

        // internal variables for ease of reference and de-duplication of code
        const _full_app_redirect_uri = 'https://' + app_callback_host + app_callback_path;

        // a function for looking up a jwt's appropriate signing key for validation
        let jwt_keys = undefined; // undefined until we load them in via http get
        let jwk_key_lookup = function(kid) {

            // we need to issue an http get to load in the jwt signing keys
            // in the future we could do some clever delay/subscription here
            // but for now we'll just kick back a failure until the key fetch completes
            if (typeof(node.jwt_keys) === "undefined") {
                cb(new Error('Keys not yet loaded'))
            }

            const key = node.jwt_keys[kid]
            if (key) {
                return key;
            }

            new Error('Unknown kid');
        };

        async function verifyJwt(jwt, jwk_key, issuer, audience) {
            const parsed_key = await parseJwk(jwk_key)
            const { payload, protectedHeader } = await jwtVerify(jwt, parsed_key, {issuer: issuer, audience: audience})
            const parsed_jwt = {payload: payload, header: protectedHeader}
            return parsed_jwt
        }
       
        async function load_jwt_keys() {
            try {
                let response = await axios.get(oauth2_jwks_url)
                if (response.status !== 200) {
                    // TODO pass this error into the node red interface too
                    console.error('Error in fetching the OAuth2 JWKs (expected a 200): ', response.status, response.data);
                }

                // for now assume the keys are in the JSON Web Key Set format
                // and so iterate to move them into a map[kid id][kid data]
                // to enable rapid lookup for verification
                let jwks_json = response.data;
                node.jwt_keys = {};
                for (const item of jwks_json.keys) {
                    node.jwt_keys[item.kid] = item;
                }

                console.log('http-in-oauth2: finished loading jwks from: ', oauth2_jwks_url)
                
            } catch (error) {
                console.error('Error in fetching the OAuth2 JWKs: ', error)
            }
        }
        load_jwt_keys();
        
        // set client and authentication information for use with the oauth flow
        const client = new AuthorizationCode({
            client: {
              id: oauth2_app_id,
              secret: oauth2_app_secret
            },
            auth: {
              tokenHost: oauth2_endpoint,
              tokenPath: oauth2_token_path,
              authorizePath: oauth2_authorize_path,
            },
        });

        // Authorization uri definition
        const authorizationUri = client.authorizeURL({
          redirect_uri: _full_app_redirect_uri,
          scope: oauth2_scopes.split('+'),
        });

        // NODE RED INPUT FUNCTION
        // this will trigger when new data is fed from node red into our state in the workflow
        // need to call done(..) to inform node red the state is finished processing  AND send(..)  
        node.on('input', function(msg, send, done) {

            // making this async here so I can use await to keep the code clean
            // of nested promises.
            async function process_input() {

                // if this is the callback, process it
                if (msg.req.route.path === app_callback_path) {
                    const { code } = msg.req.query;
                    const options = {
                        code,
                        redirect_uri: _full_app_redirect_uri,
                    };

                    // need an async function here to handle the token fetching
                    async function fetch_token() {
                        try {
                            // fetch the token set from the auth provider
                            const accessToken = await client.getToken(options);

                            // peak into the jwt to read the 'kid' value and then use the 
                            // correct signing key to do the verification
                            let jwt_key_id = decodeProtectedHeader(accessToken.token.id_token).kid;
                            let parsed_id_token = await verifyJwt(accessToken.token.id_token, jwk_key_lookup(jwt_key_id));
                            audit_event(parsed_id_token.payload.email, "authenticated"), {};

                            // set the id token in the client's cookies so they stay authed for the duration of the jwt
                            msg.res._res.cookie(app_cookie_name, accessToken.token.id_token, {httpOnly: true, secure: true});
                            msg.res._res.set('Location', '/');   // TODO pass old location through state to redirect back later
                            msg.res._res.status(302).send();

                        } catch (error) {
                            console.error('Access Token Error:', error.message, error);
                            msg.res._res.status(500).json('Authentication failed');
                        }
                        done();
                    }
                    fetch_token();
                    return;
                };

                // if this is not the callback url path, then look to see if we're already authenticated
                // by inspecting the cookie 
                if (typeof msg.req.cookies[app_cookie_name] !== "undefined") {
                    let id_token = msg.req.cookies[app_cookie_name];

                    // do a verification that the jwt is still valid
                    try {
                        let jwt_key_id = decodeProtectedHeader(id_token).kid;  // need the signing key id
                        let parsed_id_token = await verifyJwt(id_token, jwk_key_lookup(jwt_key_id));
                        audit_event(parsed_id_token.payload.email, "access", {"url": msg.req.url});

                        // pass this into the flow for later nodes to use by sending the message along
                        msg.httpInOauth2 = {};
                        msg.httpInOauth2.id_token = parsed_id_token;
                        send(msg);

                    // if it isn't, bounce the user back to the auth provider for re-authentication
                    } catch (error) {
                        audit_event(undefined, "denied", {"error": error.message, "id_token": id_token});
                        console.log(error);  // TODO change to a debug line later, but keeping for now
                        msg.res._res.set('Location', authorizationUri);
                        msg.res._res.status(302).send();
                    }

                // if our cookie is not defined, that means we need to do an authentication
                } else {
                    // Redirect over to the oauth provider for actual login
                    msg.res._res.set('Location', authorizationUri);
                    msg.res._res.status(302).send();
                }
                done();
            }
            process_input();
        });

    }
    RED.nodes.registerType("http-in-oauth2", HttpInOauth2);
}



