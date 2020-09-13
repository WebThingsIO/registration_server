# API

The API follows these general rules:
* All requests are GET requests.
* All parameters are passed as query parameters.
* CORS is enabled on endpoints that are meant to be queried by web browsers.
* 400 is returned for any client error, e.g. missing parameter, incorrect
  parameter value, etc.
* 501 is returned for internal errors, e.g. database issues.

## /subscribe

This endpoint reserves a new name for the gateway as a subdomain managed by the
registration server.

### Parameters

* `name`: the requested name to use as part of the subdomain assigned to the
  gateway.
* `desc`: optional, a friendly description of this gateway. If this parameter
  is not present, a default description is generated including the gateway's
  name.
* `email`: optional, used to determine if an existing domain is associated with
  the provided email or not.
* `reclamationToken`: optional, the reclamation token assigned to this domain.
* `mode`: optional, used to indicate whether this domain should be tunneled via
  PageKite (mode=0, default) or if we should just return the gateway's IP
  address (mode=1). In the latter mode, the registration server just acts as a
  dynamic DNS provider.

### Returns

A JSON document:
```json
{
  "name": "demo",
  "token": "asd34q343krj3"
}
```

The token is a secret identifier for this domain that must not be transmitted
to any third party.

## /unsubscribe

This endpoint lets you remove a previously subscribed domain.

### Parameters

* `token`: the secret token assigned to this domain.
* `reclamationToken`: optional, the reclamation token assigned to this domain.

### Returns

An empty HTTP 200 response.

## /reclaim

This endpoint is used to generate a reclamation token, which is used by the
`/subscribe` API to reclaim a domain.

### Parameters

* `name`: the name being reclaimed

### Returns

An empty HTTP 200 response. This will trigger an email being sent to the
registered email address with a reclaim token.

## /ping

This needs to be called on a regular basis to let the system know that the
gateway is still active. This route is also used to keep the gateway's IP
address up to date, which is needed for dynamic DNS.

### Parameters

* `token`: the secret token assigned to this domain.

### Returns

An empty HTTP 200 response.

## /dnsconfig

This endpoint is used to set the Let's Encrypt DNS challenge value when
creating or renewing certificates.

### Parameters

* `token`: the secret token assigned to this domain.
* `challenge`: the value of the challenge which will be returned in TXT DNS
  requests with an `_acme_challenge` prefix.

### Returns

An empty HTTP 200 response.

## /info

### Parameters

* `token`: the secret token assigned to this domain.

### Returns

A JSON representation of the database content for the domain matching this
token.

## /setemail

Sets the email associated with a domain.

### Parameters

* `token`: the secret token assigned to this domain.
* `email`: the email address to assign.

### Returns

An empty HTTP 200 response. This will trigger an email verification flow by
sending a message to the email address with a link to follow in order to
associate the email address with the domain.

## /verifyemail

Verifies a pending email.

### Parameters

* `s`: verification UUID

### Returns

A success page in HTML (as this is meant to be clicked on by a user).

## /revokeemail

Calling this endpoint will cancel an ongoing email verification flow.

### Parameters

* `token`: the secret token assigned to this domain.

### Returns

An empty HTTP 200 response.

## /connectivity-check

Allows users to test the connectivity of their clients.

### Parameters

None.

### Returns

String "OK"
