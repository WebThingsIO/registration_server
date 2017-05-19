# REST API

The REST api follows these general rules:
* All the requests are GET requests.
* CORS is enabled on endpoints that are meant to be queried by web browsers.
* 400 is returned for any client error (missing parameter, incorrect parameter value).
* 501 is returned for internal errors (typically database issues).

# /subscribe

This endpoint reserves a new name for the gateway, as a subdomain managed by the registration server.

*Parameters:*
* `name`: the requested name to use as part of the subdomain assigned to the gateway.
* `desc`: optional, a friendly description of this gateway. If this parameter is not present, a default description is generated including the gateway's name.

*Returns:*

A json document: `{ "name": "demo", "token": "asd34q343krj3" }`

The token is a secret identifier for this gateway, that must not be transmitted to any third party.

# /unsubscribe

This endpoint let you remove from the registration server a previously subscribed gateway.

*Parameters:*
* `token`: the secret token assigned to this gateway.

*Returns:*

An empty HTTP 200 response.

# /register

This needs to be called on a regular basis to let the system know what the local ip of the gateway is to assist with discovery. The server will evict old entries on a regular basis so the gateway needs to register itself often enough.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `local_ip`: the local ip address of the gateway.

*Returns:*

An empty HTTP 200 response.

The local ip is used to return results of the `/ping` endpoint.

# /dnsconfig

This endpoint is used to set the Let's Encrypt DNS challenge value when you need to retrieve or review certificates.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `challenge`: the value of the challenge which will be return in TXT DNS requests with an _acme_challenge prefix.

*Returns:*

An empty HTTP 200 response.

# /info

*Parameters:*
* `token`: the secret token assigned to this gateway.

*Returns:*

A json representation of the database content for the gateway matching this token.

# /ping

*No parameters*

*Returns:*

An array of `{ "href": "...", "desc": "..." }` objects each describing a gateway that can be reached on this local network.

# /adddiscovery

This endpoints binds a gateway to a discovery token. Discovery tokens are meant to only be shared by one 3rd party that can use them to discover the gateway without knowing its secret token.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `disco`: a secret discovery token.

*Returns:*

An empty HTTP 200 response.

# /revokediscovery

Remove a token <-> disco binding, making the gateway undiscoverable by a 3rd party holding on this discovery token.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `disco`: a secret discovery token.

*Returns:*

An empty HTTP 200 response.

# /discovery

This endpoint will provide the best way to reach a gateway for a 3rd party application.

*Parameters:*
* `disco`: a secret discovery token.

*Returns:*

An array of `{ "href": "...", "desc": "..." }` objects each describing a way to reach the gateway.

# /setemail

Adds a pending verification email to a gateway.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `email`: the email to verify.

*Returns:*

An empty HTTP 200 response. This will trigger an email verification flow by sending a message to the email address with a link to follow in order to associate the email address with the gateway.

# /revokeemail

Calling this endpoint will cancel an ongoing email verification flow.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `email`: the email being verified.

*Returns:*

An empty HTTP 200 response.
