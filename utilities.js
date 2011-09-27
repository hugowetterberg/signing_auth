(function() {
  var formEncode, nonce, nonceChars, normalizeParameters, percentEncode;
  nonceChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
  exports.percentEncode = percentEncode = function(s) {
    var c, e, extraEscapeCharacters, v, _i, _j, _len, _len2;
    if (s === null) {
      return "";
    }
    if (s instanceof Array) {
      e = "";
      for (_i = 0, _len = s.length; _i < _len; _i++) {
        v = s[_i];
        if (e !== "") {
          e += '&';
        }
        e += exports.percentEncode(v);
      }
      return e;
    }
    s = encodeURIComponent(s);
    extraEscapeCharacters = "!*'()";
    for (_j = 0, _len2 = extraEscapeCharacters.length; _j < _len2; _j++) {
      c = extraEscapeCharacters[_j];
      s = s.replace(c, "%" + c.charCodeAt(0).toString(16));
    }
    return s;
  };
  exports.formEncode = formEncode = function(parameters) {
    var form, key, value, _i, _len, _ref;
    form = "";
    for (_i = 0, _len = parameters.length; _i < _len; _i++) {
      _ref = parameters[_i], key = _ref[0], value = _ref[1];
      if (value === null) {
        value = "";
      }
      if (form !== "") {
        form += '&';
      }
      form += percentEncode(key) + '=' + percentEncode(value);
    }
    return form;
  };
  exports.normalizeParameters = normalizeParameters = function(parameters) {
    var key, pair, sortKey, sortable, sorted, value;
    if (!parameters) {
      return "";
    } else {
      sortable = [];
      for (key in parameters) {
        value = parameters[key];
        if (key !== "signing_signature") {
          sortKey = percentEncode(key) + " " + percentEncode(value);
          sortable.push([sortKey, [key, value]]);
        }
      }
      sortable.sort(function(a, b) {
        if (a[0] < b[0]) {
          return -1;
        } else if (a[0] > b[0]) {
          return 1;
        } else {
          return 0;
        }
      });
      sorted = (function() {
        var _i, _len, _results;
        _results = [];
        for (_i = 0, _len = sortable.length; _i < _len; _i++) {
          pair = sortable[_i];
          _results.push(pair[1]);
        }
        return _results;
      })();
      console.dir(sorted);
      return formEncode(sorted);
    }
  };
  exports.nonce = nonce = function(length) {
    var i, nlen, result, rnum;
    nlen = nonceChars.length;
    result = "";
    for (i = 1; 1 <= length ? i <= length : i >= length; 1 <= length ? i++ : i--) {
      rnum = Math.floor(Math.random() * nlen);
      result += nonceChars.substring(rnum, rnum + 1);
    }
    return result;
  };
}).call(this);
