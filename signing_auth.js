(function() {
  var SigningAuth, crypto, url, utilities;
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };
  crypto = require('crypto');
  url = require('url');
  utilities = require('./utilities');
  /*
  SigningAuth can be used to check the signature of incoming http POST requests, either manually or
  as a connect middleware. It also supports challenge-response authentication over a socket.io websocket.
  */
  exports.SigningAuth = SigningAuth = (function() {
    /*
      Constructs a signing auth object.
    
      @param storage
        An object implementing the methods checkNonce(credentials, nonce, callback) where callback is callback(error, valid) 
        and getCredentials(key, callback) where callback is callback(error, credentials).
      */    function SigningAuth(storage, connect) {
      var method, storageInterface, _i, _len;
      this.storage = storage;
      this.connect = connect != null ? connect : null;
      storageInterface = ['checkNonce', 'getCredentials'];
      for (_i = 0, _len = storageInterface.length; _i < _len; _i++) {
        method = storageInterface[_i];
        if (!(this.storage[method] != null) || typeof this.storage[method] !== 'function') {
          throw new Error("The provided storage object doesn't implement " + method + "()");
        }
      }
      null;
    }
    /*
      Checks the signature of a parsed url.
      */
    SigningAuth.prototype.validateSignature = function(puri, requestReceived, credentials, callback) {
      var key, now, request_max_time_diff, required, timestamp, _i, _len;
      required = ['signing_key', 'signing_nonce', 'signing_body_hash', 'signing_signature', 'signing_timestamp'];
      for (_i = 0, _len = required.length; _i < _len; _i++) {
        key = required[_i];
        if (!(puri.query[key] != null)) {
          callback(new Error("Missing required parameter " + key));
          return;
        }
      }
      request_max_time_diff = 60;
      timestamp = parseInt(puri.query.signing_timestamp, 10);
      now = requestReceived.getTime() / 1000;
      if (timestamp < (now - request_max_time_diff)) {
        callback(new Error("Request timestamp too old, must not be older than " + request_max_time_diff + " seconds"));
      } else if (timestamp > (now + request_max_time_diff)) {
        callback(new Error("Request timestamp from the future, that doesn't work you know."));
      } else {
        this.storage.checkNonce(credentials, puri.query.signing_nonce, function(error, valid) {
          var base, hmac, signature;
          if (error) {
            callback(new Error("Could not check the nonce"));
          } else if (!valid) {
            callback(new Error("Nonce was not unique, please generate a new nonce and retry the request"));
          } else {
            hmac = crypto.createHmac('sha256', credentials.secret);
            base = utilities.normalizeParameters(puri.query);
            hmac.update(base);
            signature = hmac.digest('base64');
            if (signature === puri.query.signing_signature) {
              callback(false, true);
            } else {
              callback(new Error('Invalid signature'));
            }
          }
          return null;
        });
      }
      return null;
    };
    /*
      Connect middleware that will parse the request and check it's signature.
      Two attributes will be appended to the request: body and signedBy; where
      body will be the parsed request body, and signedBy the credentials of the
      client that made the request, or false if the request wasn't properly signed.
      */
    SigningAuth.prototype.connectMiddleware = function() {
      var justParseBody, serveStatic;
      justParseBody = function(req, next) {
        var data;
        data = '';
        req.on('data', function(chunk) {
          return data += chunk;
        });
        return req.on('end', function() {
          try {
            req.body = JSON.parse(data);
          } catch (error) {
            return next(error);
          }
          return next();
        });
      };
      serveStatic = this.connect ? this.connect.static(__dirname + '/public_html') : function(req, res, next) {
        return next();
      };
      return __bind(function(req, res, next) {
        var puri;
        if (req.body) {
          return next();
        }
        req.body = {};
        req.signedBy = false;
        puri = url.parse(req.url, true);
        if (req.method !== 'POST') {
          if (req.method === 'GET' && puri.pathname.indexOf('/signing.auth/') === 0) {
            return serveStatic(req, res, next);
          } else {
            return next();
          }
        } else if (!(puri.query.signing_signature != null)) {
          return justParseBody(req, next);
        } else {
          return this.parseRequest(req, function(error, body, puri, credentials) {
            if (error) {
              return next(error);
            } else {
              req.body = body;
              req.signedBy = credentials;
              return next();
            }
          });
        }
      }, this);
    };
    /*
      Parse a request and check its signature.
    
      @param req
        The http server request object.
      @param callback
        A callback function taking the following parameters:
        error, body, puri and credentials
      */
    SigningAuth.prototype.parseRequest = function(req, callback) {
      var data, puri, requestReceived, shasum;
      req.setEncoding('utf-8');
      shasum = crypto.createHash('sha256');
      puri = url.parse(req.url, true);
      requestReceived = new Date();
      data = '';
      req.on('data', function(chunk) {
        data += chunk;
        return shasum.update(chunk);
      });
      return req.on('end', __bind(function() {
        return this.storage.getCredentials(puri.query.signing_key, __bind(function(error, credentials) {
          if (!credentials || error) {
            return callback(new Error('Unknown API key', 1001));
          } else {
            return this.validateSignature(puri, requestReceived, credentials, function(error, valid) {
              var body, body_hash;
              if (error) {
                return callback(error);
              } else {
                body_hash = shasum.digest('base64');
                if (!(body_hash === puri.query.signing_body_hash)) {
                  return callback(new Error('Invalid body hash', 1000));
                } else {
                  body = JSON.parse(data);
                  return callback(false, body, puri, credentials);
                }
              }
            });
          }
        }, this));
      }, this));
    };
    /*
      Starts a challenge-response handshake on a web-socket.
      */
    SigningAuth.prototype.issueChallenge = function(socket, callback) {
      var challenge, newChallenge;
      challenge = null;
      newChallenge = function() {
        challenge = utilities.nonce(64);
        socket.emit('challenge', {
          sign: challenge
        });
        return null;
      };
      socket.on('challenge-response', __bind(function(data) {
        var failed, key;
        key = data.key;
        failed = function(msg) {
          challenge = null;
          socket.emit('challenge-failed', {
            message: msg
          });
          callback(new Error(msg));
          newChallenge();
          return null;
        };
        if (!challenge) {
          failed("Operation out of order, no challenge has been issued");
        }
        this.storage.getCredentials(key, function(error, credentials) {
          var hmac, signature;
          if (error) {
            failed("Could not load credentials for " + key);
          } else if (!credentials) {
            failed("Could not find the account " + key);
          } else {
            hmac = crypto.createHmac('sha1', credentials.secret);
            hmac.update(key);
            hmac.update(challenge);
            signature = hmac.digest('hex');
            if (signature !== data.signature) {
              failed("Signature mismatch");
            } else {
              socket.emit('challenge-success', {
                key: credentials.key,
                admin: credentials.admin
              });
              callback(false, credentials);
            }
          }
          return null;
        });
        return null;
      }, this));
      return newChallenge();
    };
    return SigningAuth;
  })();
}).call(this);
