# Actors

* **gateway**: The IoT gateway running on the local network.
* **cloud**: The registration server/DNS/PageKite combo.
    * All API calls to the registration server are done through TLS, assuming the server is properly configured.
    * PageKite tunnels are set up with unique secret tokens for each domain.
* **LE**: [Let's Encrypt](https://letsencrypt.org/)
* **browser**: The user's web browser.
* **email**: The user's email.

# Gateway Setup

1.  **[gateway <-> browser]** Start the gateway server on HTTP and load the setup UI at http://gateway.local:8080
2.  **[gateway <-> cloud]** Choose an available domain name and receive the API token using `/subscribe`.
3.  **[gateway <-> LE]** Run the Let's Encrypt DNS challenge on the gateway.
4.  **[gateway <-> cloud]** Use `/dnsconfig` to send the LE challenge token to the registration server.
5.  **[LE <-> cloud]** LE does a DNS lookup for the desired domain. Lookup is handled by registration server, and the challenge token is returned.
6.  **[gateway <-> LE]** Generate the certificates, restart the server on HTTPS.
7.  **[gateway <-> cloud]** Gateway sets up a secure tunnel to the registration server through PageKite. This makes the gateway UI accessible through the internet, at the desired domain, with no extra effort by the user.
8.  **[gateway <-> browser]** Redirect from http://gateway.local:8080 to https://mydomain.mozilla-iot.org.
9.  **[gateway <-> browser]** Create the gateway admin account with an email address.
10. **[gateway <-> cloud]** Set domain's email address with `/setemail`.
11. **[cloud <-> email]** Registration server sends a verification email to the provided email address, with a `/verifyemail` link.
12. **[email <-> browser]** Domain is verified by clicking the provided `/verifyemail` link.
13. **[gateway <-> cloud]** Periodically ping the cloud service using `/ping`.
14. **[gateway <-> LE]** Service runs in the background on the gateway and auto-renews its LE certificates as necessary.

# Domain Reclamation

1.  **[gateway <-> browser]** Start the server on HTTP and load the setup UI at http://gateway.local:8080
2.  **[gateway <-> cloud]** User chooses a domain name they've already used (determined via `/subscribe`) and is given the option to reclaim.
3.  **[gateway <-> cloud]** Gateway calls `/reclaim`.
4.  **[cloud <-> email]** A random reclamation token is generated and emailed to the registered email address.
5.  **[email <-> browser]** User enters the reclamation token from their email into the gateway's setup UI.
6.  **[gateway <-> cloud]** Gateway again calls `/subscribe` with the reclamation token and receives an API token.
7.  **[gateway <-> LE]** Run the Let's Encrypt DNS challenge on the gateway.
8.  **[gateway <-> cloud]** Use `/dnsconfig` to send the LE challenge token to the registration server.
9.  **[LE <-> cloud]** LE does a DNS lookup for the desired domain. Lookup is handled by registration server, and the challenge token is returned.
10. **[gateway <-> LE]** Generate the certificates, restart the server on HTTPS.
11. **[gateway <-> cloud]** Gateway sets up a secure tunnel to the registration server through PageKite. This makes the gateway UI accessible through the internet, at the desired domain, with no extra effort by the user.
12. **[gateway <-> browser]** Redirect from http://gateway.local:8080 to https://mydomain.mozilla-iot.org.
13. **[gateway <-> browser]** Create the gateway admin account with an email address.
14. **[gateway <-> cloud]** Periodically ping the cloud service using `/ping`.
15. **[gateway <-> LE]** Service runs in the background on the gateway and auto-renews its LE certificates as necessary.
