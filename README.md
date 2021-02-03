
## OAuth2 Client for Node Red

This project adds a new node to node red that allows Http In nodes to be authenticated against the OAuth2 provider of your choice.  

If you'll excuse my poor attempt at ascii art here, the minimum configuration is as follows:

```
HTTP In (/)       ------>       |
                                |   -->  http-in-oauth2  --> Http Response (200)
HTTP In (/oauth2/callback) -->  |
```

The above configuration gives you the path you want to protect (/), as well as a callback URL that the OAuth provider can call back to you add (/oauth2/callback).  The OAuth2 node will use HTTP redirects (status code 302's) to send non-authenticated users over to your OAuth provider.  Once successfully authenticated, the the OAuth node will add a cookie to the user's browser allowing them to remain authenticated for the duration their OAuth token is valid. 

### Things to note:
* A logout flow is not implemented (yet). 
* This node was built, designed, and tested against AWS Cognito's OAuth provider. It _should_ work for others too, but there many be issue depending on the different flavors of OAuth implementations out there.
* This node handles **authentication** but not *authorization*.  That is left up to the nodes in the flow after this one. The openid token is added to the `msg` output of this node so you'll have full access to the user's identity to make access decisions with.

## Node Settings

A quick list of the settings on this node. For more detail see either the HTML file or pull up the configuration interface in Node Red.

`auth-endpoint` - the OAuth2 host (start with https://, only include host name, no paths)
`auth-authorize-path` -  the path to authorize from the host e.g.  /oauth2/authorize
`auth-token-path` - the path to the token api endpoint e.g. /oauth2/token
`auth-scopes` - the scopes to request from the OAuth2 host
`auth-app-id` - the application/client ID to use when talking to the oauth server
`auth-app-secret` - the app/client secret to use when calling the token endpoint
`auth-jwks-url` - a url containing the public keys used to sign the JWTs
`callback-host` - the node red server 
`callback-path` - the callback path. we'll listen on that and do redirects when auth is missing
`auth-cookie-name` - the name of the cookie we'll store the OAuth ID token in

## Node Output

If there are no errors during authentication, this node writes a new object to the `msg` object called `httpInOauth2`.  It has a single entry called `id_token` which is the parsed and validated openid JWT which identifies the authenticated user.

