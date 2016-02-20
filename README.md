# Registration server

This server listen on port 4242 and let you register devices from your home network and discover them later on.

## Urls

Two endpoints are provided:

1. /register?ip=XXX will register `ip` as a local ip associated to your current network.
2. /ping will return a json representation of the endpoints that are bound to the current public ip of the request.
