Signing Auth
=================

Simple request signing authentication based on OAuth but greatly simplified. Useful when you need simple authentication of POST request between the server and client. SigningAuth can be used to check the signature of incoming http POST requests, either manually or as a connect middleware. It also supports challenge-response authentication over a socket.io websocket.

For a example of how to make a signed request from PHP/Drupal take a look at: [http_client_signing_auth](http://github.com/hugowetterberg/http_client_signing_auth)

See the [sample application](https://github.com/hugowetterberg/signing_auth/blob/master/sample_application/) for an example of the browser-based challenge-response authentication.
