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
* `reclamationToken`: optional, randomly generated token used to reclaim the domain.

*Returns:*

A json document: `{ "name": "demo", "token": "asd34q343krj3" }`

The token is a secret identifier for this gateway, that must not be transmitted to any third party.

# /unsubscribe

This endpoint let you remove from the registration server a previously subscribed gateway.

*Parameters:*
* `token`: the secret token assigned to this gateway.

*Returns:*

An empty HTTP 200 response.

# /reclaim

This endpoint is used to generate a reclamation token, which is used by the /subscribe API to reclaim a domain.

*Parameters:*
* `name`: the name being reclaimed

*Returns:*

An empty HTTP 200 response. This will trigger an email being sent to the registered email address with a reclaim token.

# /ping

This needs to be called on a regular basis to let the system know that the gateway is still active.

*Parameters:*
* `token`: the secret token assigned to this gateway.

*Returns:*

An empty HTTP 200 response.

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

# /setemail

Adds a pending verification email to a gateway.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `email`: the email to verify.

*Returns:*

An empty HTTP 200 response. This will trigger an email verification flow by sending a message to the email address with a link to follow in order to associate the email address with the gateway.

# /verifyemail

Verifies a pending email.

*Parameters:*
* `s`: verification uuid

*Returns:*

A success page in HTML (as this is meant to be clicked on by a user).

# /revokeemail

Calling this endpoint will cancel an ongoing email verification flow.

*Parameters:*
* `token`: the secret token assigned to this gateway.
* `email`: the email being verified.

*Returns:*

An empty HTTP 200 response.
