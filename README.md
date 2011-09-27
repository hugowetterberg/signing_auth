Signing Auth
=================

Simple request signing authentication based on OAuth but greatly simplified. Useful when you need simple authentication of POST request between the server and client. SigningAuth can be used to check the signature of incoming http POST requests, either manually or as a connect middleware. It also supports challenge-response authentication over a socket.io websocket.

For a example of how to make a signed request from PHP/Drupal take a look at: [http_client_signing_auth](http://github.com/hugowetterberg/http_client_signing_auth)

Here's an abridged coffe-script example of how a websocket client can connect using signing auth with help from the excellent [Crypto library](http://code.google.com/p/crypto-js/), see [tattlebird_server](https://github.com/hugowetterberg/tattlebird-server/blob/master/public_html/js/app.coffee) for a full example:

    socket.on 'challenge-failed', (data)->
      console.log "Noo, it didn't work because: #{data.message}"

    socket.on 'challenge-success', (data)->
      console.log "Yay! We're authenticated, moving on"

    socket.on 'challenge', (data, callback)->
      console.log "Got challenge asking us to sign #{data.sign}"

      $ ()->
        $('form.login').unbind().bind 'submit', (event)->
          values = {}
          for pair in $(this).serializeArray()
            values[pair.name] = pair.value

          # Saving credentials
          localStorage['tattlebird_key'] = values.username
          localStorage['tattlebird_secret'] = values.password

          signature = Crypto.HMAC(Crypto.SHA1, values.username + data.sign, values.password)
          console.log "Sending user response signature #{signature} for key #{values.username}"
          callback
            key: values.username
            signature: signature
          no

      if localStorage.tattlebird_key?
        key = localStorage['tattlebird_key']
        secret = localStorage['tattlebird_secret']
        signature = Crypto.HMAC(Crypto.SHA1, key + data.sign, secret)
        console.log "Sending automatic response signature #{signature} for key #{key}"
        callback
          key: key
          signature: signature
      else
        # Show login form
