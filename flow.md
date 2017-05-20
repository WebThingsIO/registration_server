# Actors

[gateway] the IoT gateway running in the local network.

[cloud] is the registration+dns+tunnel combo.

[app] is a 3rd party web application that will access [gateway] on behalf of the end user.

[browser] is the user's web browser.

# Setup

1. [gateway <-> browser] Start the server on http and load the setup UI at http://localhost:8080
2. [gateway <-> cloud] Find an available DNS name, receive the api token using `/subscribe`.
3. [gateway <-> cloud] Run the LE DNS challenge, use `/dnsconfig`, retrieve the certificates, restart the server on https.
4. [gateway <-> browser] Create the admin account with an email address, verify email using `/setemail`.
5. [gateway <-> cloud] periodically register the server local ip with the cloud service using `/register`.

# Discovery

The registration server supports two kinds of discovery mechanism:

* A simple one, using a single DNS name per gateway, that doesn't provide shortest path in the local network out of the box.
* A more evolved one combining two DNS names, that let 3rd party applications discover the shortest path to access the gateway apis.

In each case, we consider that the gateway has been subscribed successfully and that the relevant TLS certificates are installed.

The gateway is then in nominal working mode, in which it periodically calls the `/register` endpoint.

## Simple discovery

In this mode, the browser calls the `/ping` endpoint and will either receive a list of local gateways or an empty answer if the user is browsing from outside the local network. This means that the web application must first be used in the local network and remember the gateway url. The DNS will also always resolve this url as a public ip, forcing a round trip through the tunnel.

## Full discovery

This mode relies on the set of `discovery` endpoints and works as follows:

When the [app] at https://example.com/ wants to access the services on the gateway:

First use:
1. [browser] needs to be connected on the local network.
2. [app <-> cloud] triggers a discovery and presents choices to the user if there are several options (using `/ping`).
3. [app] Opens an iframe to https://server/auth?redirect=https://example.com/auth_done
4. [app] Retrieves the app specific tokens (authentication and discovery ones) to present for REST requests to [server] and discovery requests to [cloud] (using `/adddiscovery` from the gateway to the cloud).

Subsequent uses:
1. [app] uses its discovery token to discover the [server] location.
2. [app] calls [server] apis using its authentication token.

In this case, the `/discovery` endpoint called from the browser will provide a different DNS name depending on whether the call is made from within the local network or not.

# Email verification

1. The admin UI calls `/setemail`, which triggers the sending of a verification email.
2. When the user clicks on the link from the email, this validates the email as being associated with the gateway.
3. It is possible to check if an email is setup by calling the `/info` endpoint.
