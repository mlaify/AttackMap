const jwt = require('jsonwebtoken')
const keys = require('./keys')

function requirePartner(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString())
  try {
    req.partner = jwt.verify(token, keys.partnerKey(header))
    next()
  } catch (err) {
    res.status(401).end()
  }
}

module.exports = { requirePartner }
