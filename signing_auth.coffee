crypto = require 'crypto'
url = require 'url'
utilities = require './utilities'

###
SigningAuth can be used to check the signature of incoming http POST requests, either manually or
as a connect middleware. It also supports challenge-response authentication over a socket.io websocket.
###

exports.SigningAuth = class SigningAuth

  ###
  Constructs a signing auth object.

  @param storage
    An object implementing the methods checkNonce(credentials, nonce, callback) where callback is callback(error, valid) 
    and getCredentials(key, callback) where callback is callback(error, credentials).
  ###
  constructor: (@storage, @connect = null)->
    storageInterface = ['checkNonce', 'getCredentials']
    for method in storageInterface
      if not @storage[method]? or typeof @storage[method] isnt 'function'
        throw new Error "The provided storage object doesn't implement #{method}()"
    null

  ###
  Checks the signature of a parsed url.
  ###
  validateSignature: (puri, requestReceived, credentials, callback)->
    # Check that we have all required fields.
    required = ['signing_key', 'signing_nonce', 'signing_body_hash', 'signing_signature', 'signing_timestamp']
    for key in required
      if not puri.query[key]?
        callback new Error("Missing required parameter #{key}")
        return

    # Allow for some timestamp difference.
    request_max_time_diff = 60
    timestamp = parseInt(puri.query.signing_timestamp, 10)
    now = requestReceived.getTime() / 1000
    if timestamp < (now - request_max_time_diff)
      callback new Error("Request timestamp too old, must not be older than #{request_max_time_diff} seconds")
    else if timestamp > (now + request_max_time_diff)
      callback new Error("Request timestamp from the future, that doesn't work you know.")
    else
      # Check the nonce.
      @storage.checkNonce credentials, puri.query.signing_nonce, (error, valid)->
        if error
          callback new Error("Could not check the nonce")
        else if not valid
          callback new Error("Nonce was not unique, please generate a new nonce and retry the request")
        else
          # Build signature
          hmac = crypto.createHmac 'sha256', credentials.secret
          base = utilities.normalizeParameters puri.query
          hmac.update base
          signature = hmac.digest 'base64'

          # Verify signature
          if signature is puri.query.signing_signature
            callback no, yes
          else
            callback new Error('Invalid signature')
        null
    null

  ###
  Connect middleware that will parse the request and check it's signature.
  Two attributes will be appended to the request: body and signedBy; where
  body will be the parsed request body, and signedBy the credentials of the
  client that made the request, or false if the request wasn't properly signed.
  ###
  connectMiddleware: ()->
    # Utility function used if the request isn't signed at all then
    # we just want to parse the body, and let signedBy be false.
    justParseBody = (req, next)->
      data = ''
      req.on 'data', (chunk)->
        data += chunk
      req.on 'end', ()->
        try
          req.body = JSON.parse(data)
        catch error
          return next(error)
        next()

    serveStatic = if @connect
      @connect.static(__dirname + '/public_html')
    else
      (req, res, next)->
        next()

    (req, res, next)=>
      if req.body
        return next()
      req.body = {}
      req.signedBy = no

      puri = url.parse req.url, yes

      # Signing auth only deals with POST requests.
      if req.method isnt 'POST'
        if req.method is 'GET' and puri.pathname.indexOf('/signing.auth/') is 0
          serveStatic(req, res, next)
        else
          next()
      # Let unsigned request pass through with just body parsing.
      else if not puri.query.signing_signature?
        return justParseBody req, next
      else
        @parseRequest req, (error, body, puri, credentials)->
          if error
            next(error)
          else
            req.body = body
            req.signedBy = credentials
            next()

  ###
  Parse a request and check its signature.

  @param req
    The http server request object.
  @param callback
    A callback function taking the following parameters:
    error, body, puri and credentials
  ###
  parseRequest: (req, callback)->
    req.setEncoding 'utf-8'
    shasum = crypto.createHash 'sha256'
    puri = url.parse req.url, yes

    requestReceived = new Date()

    data = ''
    req.on 'data', (chunk)->
      data += chunk
      shasum.update chunk
    req.on 'end', ()=>
      @storage.getCredentials puri.query.signing_key, (error, credentials)=>
        if not credentials or error
          callback new Error('Unknown API key', 1001)
        else
          # Validate get-parameter signature.
          @validateSignature puri, requestReceived, credentials, (error, valid)->
            if error
              callback error
            else
              # Validate body hash.
              body_hash = shasum.digest('base64')
              if not (body_hash is puri.query.signing_body_hash)
                callback new Error('Invalid body hash', 1000)
              else
                body = JSON.parse(data)
                callback false, body, puri, credentials

  ###
  Starts a challenge-response handshake on a web-socket.
  ###
  issueChallenge: (socket, callback)->
    challenge = null
    newChallenge = ()->
      challenge = utilities.nonce(64)
      socket.emit 'challenge', sign:challenge
      null

    socket.on 'challenge-response', (data)=>
      key = data.key

      # Helper function to send a failure response.
      failed = (msg)->
        challenge = null
        socket.emit 'challenge-failed', message: msg
        callback new Error(msg)
        newChallenge()
        null

      if not challenge
        failed "Operation out of order, no challenge has been issued"

      @storage.getCredentials key, (error, credentials)->
        if error
          failed "Could not load credentials for #{key}"
        else if not credentials
          failed "Could not find the account #{key}"
        else
          # Calculate the expected signature.
          hmac = crypto.createHmac 'sha1', credentials.secret
          hmac.update key
          hmac.update challenge
          signature = hmac.digest 'hex'

          if signature isnt data.signature
            failed "Signature mismatch"
          else
            socket.emit 'challenge-success',
              key: credentials.key
              admin: credentials.admin
            callback no, credentials
        null
      null

    newChallenge()

