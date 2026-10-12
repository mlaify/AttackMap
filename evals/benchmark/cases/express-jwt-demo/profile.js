const jwt = require('jsonwebtoken')

function me(req, res) {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const claims = jwt.decode(token)
  if (!claims) return res.status(401).end()
  res.json({ user: claims.sub, role: claims.role })
}

module.exports = { me }
