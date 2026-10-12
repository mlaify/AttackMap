const jwt = require('jsonwebtoken')
const keys = require('./keys')

function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const { header } = jwt.decode(token, { complete: true }) || {}
  try {
    req.admin = jwt.verify(token, keys.adminKey(header || {}), { algorithms: ['RS256'], audience: 'admin' })
    next()
  } catch (err) {
    res.status(401).end()
  }
}

module.exports = { requireAdmin }
