const jwt = require('jsonwebtoken')

function currentUser(req) {
  const claims = jwt.decode(req.headers.authorization.slice(7))
  return claims.sub
}

module.exports = { currentUser }
