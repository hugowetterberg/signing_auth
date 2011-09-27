
nonceChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz"

exports.percentEncode = percentEncode = (s)->
  if s is null
    return ""
  if s instanceof Array
    e = ""
    for v in s
      if e isnt "" then e += '&'
      e += exports.percentEncode v
    return e
  s = encodeURIComponent s
  extraEscapeCharacters = "!*'()"
  for c in extraEscapeCharacters
    s = s.replace c, "%" + c.charCodeAt(0).toString(16)
  return s

exports.formEncode = formEncode = (parameters)->
  form = ""
  for [key, value] in parameters
    if value is null then value = ""
    if form isnt "" then form += '&'
    form += percentEncode(key) + '=' + percentEncode(value)
  form

exports.normalizeParameters = normalizeParameters = (parameters)->
    if not parameters
      return ""
    else
      sortable = []
      for key, value of parameters
        if key isnt "signing_signature"
          sortKey = percentEncode(key) + " " + percentEncode(value)
          sortable.push [sortKey, [key, value]]
      sortable.sort (a, b)->
        if a[0] < b[0] then -1
        else if (a[0] > b[0]) then 1
        else 0

      sorted = for pair in sortable then pair[1]
      console.dir sorted
      formEncode sorted

exports.nonce = nonce = (length)->
  nlen = nonceChars.length
  result = ""
  for i in [1..length]
    rnum = Math.floor(Math.random() * nlen)
    result += nonceChars.substring(rnum, rnum+1)
  result
