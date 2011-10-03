(function() {
  var __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };
  (function() {
    var Crypto, SigningAuth;
    Crypto = {};
    /*
   * Crypto-JS v2.4.0
   * http://code.google.com/p/crypto-js/
   * Copyright (c) 2011, Jeff Mott. All rights reserved.
   * http://code.google.com/p/crypto-js/wiki/License
   */
  if(true)(function(){var i=Crypto,n=i.util={rotl:function(a,c){return a<<c|a>>>32-c},rotr:function(a,c){return a<<32-c|a>>>c},endian:function(a){if(a.constructor==Number)return n.rotl(a,8)&16711935|n.rotl(a,24)&4278255360;for(var c=0;c<a.length;c++)a[c]=n.endian(a[c]);return a},randomBytes:function(a){for(var c=[];a>0;a--)c.push(Math.floor(Math.random()*256));return c},bytesToWords:function(a){for(var c=[],b=0,d=0;b<a.length;b++,d+=8)c[d>>>5]|=a[b]<<24-
  d%32;return c},wordsToBytes:function(a){for(var c=[],b=0;b<a.length*32;b+=8)c.push(a[b>>>5]>>>24-b%32&255);return c},bytesToHex:function(a){for(var c=[],b=0;b<a.length;b++){c.push((a[b]>>>4).toString(16));c.push((a[b]&15).toString(16))}return c.join("")},hexToBytes:function(a){for(var c=[],b=0;b<a.length;b+=2)c.push(parseInt(a.substr(b,2),16));return c},bytesToBase64:function(a){if(typeof btoa=="function")return btoa(j.bytesToString(a));for(var c=[],b=0;b<a.length;b+=3)for(var d=a[b]<<16|a[b+1]<<
  8|a[b+2],e=0;e<4;e++)b*8+e*6<=a.length*8?c.push("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(d>>>6*(3-e)&63)):c.push("=");return c.join("")},base64ToBytes:function(a){if(typeof atob=="function")return j.stringToBytes(atob(a));a=a.replace(/[^A-Z0-9+\/]/ig,"");for(var c=[],b=0,d=0;b<a.length;d=++b%4)d!=0&&c.push(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(a.charAt(b-1))&Math.pow(2,-2*d+8)-1)<<d*2|"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(a.charAt(b))>>>
  6-d*2);return c}};i=i.charenc={};i.UTF8={stringToBytes:function(a){return j.stringToBytes(unescape(encodeURIComponent(a)))},bytesToString:function(a){return decodeURIComponent(escape(j.bytesToString(a)))}};var j=i.Binary={stringToBytes:function(a){for(var c=[],b=0;b<a.length;b++)c.push(a.charCodeAt(b)&255);return c},bytesToString:function(a){for(var c=[],b=0;b<a.length;b++)c.push(String.fromCharCode(a[b]));return c.join("")}}})();
  (function(){var i=Crypto,n=i.util,j=i.charenc,a=j.UTF8,c=j.Binary,b=i.SHA1=function(d,e){var f=n.wordsToBytes(b._sha1(d));return e&&e.asBytes?f:e&&e.asString?c.bytesToString(f):n.bytesToHex(f)};b._sha1=function(d){if(d.constructor==String)d=a.stringToBytes(d);var e=n.bytesToWords(d),f=d.length*8;d=[];var k=1732584193,g=-271733879,l=-1732584194,m=271733878,o=-1009589776;e[f>>5]|=128<<24-f%32;e[(f+64>>>9<<4)+15]=f;for(f=0;f<e.length;f+=16){for(var q=k,r=g,s=l,t=m,u=o,h=0;h<80;h++){if(h<16)d[h]=e[f+
  h];else{var p=d[h-3]^d[h-8]^d[h-14]^d[h-16];d[h]=p<<1|p>>>31}p=(k<<5|k>>>27)+o+(d[h]>>>0)+(h<20?(g&l|~g&m)+1518500249:h<40?(g^l^m)+1859775393:h<60?(g&l|g&m|l&m)-1894007588:(g^l^m)-899497514);o=m;m=l;l=g<<30|g>>>2;g=k;k=p}k+=q;g+=r;l+=s;m+=t;o+=u}return[k,g,l,m,o]};b._blocksize=16;b._digestsize=20})();
  (function(){var i=Crypto,n=i.util,j=i.charenc,a=j.UTF8,c=j.Binary;i.HMAC=function(b,d,e,f){if(d.constructor==String)d=a.stringToBytes(d);if(e.constructor==String)e=a.stringToBytes(e);if(e.length>b._blocksize*4)e=b(e,{asBytes:true});var k=e.slice(0);e=e.slice(0);for(var g=0;g<b._blocksize*4;g++){k[g]^=92;e[g]^=54}b=b(k.concat(b(e.concat(d),{asBytes:true})),{asBytes:true});return f&&f.asBytes?b:f&&f.asString?c.bytesToString(b):n.bytesToHex(b)}})();
  ;
    window.SigningAuth = SigningAuth = (function() {
      SigningAuth.prototype.handlers = {};
      SigningAuth.prototype.challenge = null;
      SigningAuth.prototype.automaticResponse = false;
      SigningAuth.prototype.automaticResponseFailed = false;
      SigningAuth.prototype.bind = function(event, fn) {
        if (!(this.handlers[event] != null)) {
          this.handlers[event] = [];
        }
        return this.handlers[event].push(fn);
      };
      SigningAuth.prototype.unbind = function(event, fn) {
        var idx;
        if (fn == null) {
          fn = false;
        }
        if (this.handlers[event] != null) {
          if (fn) {
            return delete this.handlers[event];
          } else {
            idx = this.handlers.indexOf(fn);
            return delete this.handlers[idx];
          }
        }
      };
      SigningAuth.prototype.trigger = function(event) {
        var args, handler, _i, _len, _ref, _results;
        if (this.handlers[event] != null) {
          args = Array.prototype.slice.call(arguments, 1);
          _ref = this.handlers[event];
          _results = [];
          for (_i = 0, _len = _ref.length; _i < _len; _i++) {
            handler = _ref[_i];
            _results.push(handler.apply(this, args));
          }
          return _results;
        }
      };
      function SigningAuth(socket, storage, key, secret) {
        this.socket = socket;
        this.storage = storage != null ? storage : false;
        this.key = key != null ? key : false;
        this.secret = secret != null ? secret : false;
        this.socket.on('challenge-failed', __bind(function(data) {
          console.log("Challenge failed " + data.message);
          if (this.storage) {
            delete this.storage['signature_key'];
            delete this.storage['signature_secret'];
          }
          this.trigger('failed', data, this.automaticResponse);
          if (this.automaticResponse) {
            this.automaticResponseFailed = true;
          }
          return this.automaticResponse = false;
        }, this));
        this.socket.on('challenge-success', __bind(function(data) {
          console.log("Challenge success");
          return this.trigger('success', data);
        }, this));
        this.socket.on('challenge', __bind(function(data) {
          this.challenge = data.sign;
          console.log("Got challenge asking us to sign " + data.sign);
          if (!this.automaticResponseFailed && this.storage && (this.storage['signature_key'] != null) && (this.storage['signature_secret'] != null)) {
            console.log("Trying an automatic response");
            this.automaticResponse = true;
            return this.response(this.storage['signature_key'], this.storage['signature_secret']);
          } else {
            console.log("Triggering a challenge event");
            this.automaticResponse = false;
            return this.trigger('challenge', data, false);
          }
        }, this));
      }
      SigningAuth.prototype.clearCredentials = function() {
        if (this.storage) {
          delete this.storage['signature_key'];
          return delete this.storage['signature_secret'];
        }
      };
      SigningAuth.prototype.response = function(key, secret) {
        var signature;
        if (this.storage) {
          this.storage['signature_key'] = key;
          this.storage['signature_secret'] = secret;
        }
        this.trigger('responding', this.automaticResponse);
        console.log("Signing " + key + this.challenge + " with " + secret);
        signature = Crypto.HMAC(Crypto.SHA1, key + this.challenge, secret);
        return socket.emit('challenge-response', {
          key: key,
          signature: signature
        });
      };
      return SigningAuth;
    })();
    return null;
  })();
}).call(this);
