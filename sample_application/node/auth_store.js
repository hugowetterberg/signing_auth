(function() {
  /*
  Sample store for signing auth.
  */
  var Store;
  module.exports = Store = (function() {
    function Store() {
      null;
    }
    Store.prototype.checkNonce = function(credentials, nonce, callback) {
      callback(false, true);
      return null;
    };
    Store.prototype.getCredentials = function(key, callback) {
      if (key === 'foo') {
        return callback(false, {
          key: 'foo',
          secret: 'bar'
        });
      } else if (key === 'fail') {
        return callback(new Error('Simulated failure'), null);
      } else {
        return callback(false, null);
      }
    };
    return Store;
  })();
}).call(this);
