socket_io = require 'socket.io'
express = require 'express'
SigningAuth = require('../../signing_auth').SigningAuth
AuthStore = require './auth_store'

authStore = new AuthStore()
auth = new SigningAuth(authStore, express)

app = express.createServer()
app.use(auth.connectMiddleware())
app.use(express.static(__dirname + '/..'))
app.io = socket_io.listen(app)

app.io.sockets.on 'connection', (socket)->
  auth.issueChallenge socket, (error, credentials)->
    console.log "We're on!"

app.listen(8088)