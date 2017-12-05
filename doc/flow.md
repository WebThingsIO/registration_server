# Actors

[gateway] the IoT gateway running in the local network.

[cloud] is the registration+dns+tunnel combo.

[app] is a 3rd party web application that will access [gateway] on behalf of the end user.

[browser] is the user's web browser.

# Setup

1. [gateway <-> browser] Start the server on HTTP and load the setup UI at http://localhost:8080
2. [gateway <-> cloud] Find an available DNS name, receive the API token using `/subscribe`.
3. [gateway <-> cloud] Run the LE DNS challenge, use `/dnsconfig`, retrieve the certificates, restart the server on HTTPS.
4. [gateway <-> browser] Create the admin account with an email address, set email with `/setemail' and verify using `/verifyemail`.
5. [gateway <-> cloud] Periodically ping the cloud service using `/ping`.

# Email verification

1. The admin UI calls `/setemail`, which triggers the sending of a verification email.
2. When the user clicks on the link from the email, this validates the email as being associated with the gateway (via `/verifyemail`).
3. It is possible to check if an email is setup by calling the `/info` endpoint.

# Domain Reclamation

1. [gateway <-> browser] Start the server on HTTP and load the setup UI at http://localhost:8080
2. [gateway <-> cloud] User chooses a DNS name already in use (determined via `/subscribe`) and is given the option to reclaim.
3. [gateway <-> cloud] Gateway calls `/reclaim`. A random reclamation token is generated and emailed to the registered email address.
4. [gateway <-> browser] User enters the reclamation token.
5. [gateway <-> cloud] Gateway again calls `/subscribe` with the reclamation token, receives and API token.
6. [gateway <-> cloud] Run the LE DNS challenge, use `/dnsconfig`, retrieve the certificates, restart the server on HTTPS.
7. [gateway <-> browser] Create the admin account with an email address, set email with `/setemail' and verify using `/verifyemail`.
8. [gateway <-> cloud] Periodically ping the cloud service using `/ping`.
