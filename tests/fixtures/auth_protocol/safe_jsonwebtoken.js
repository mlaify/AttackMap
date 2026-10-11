const jwt = require('jsonwebtoken')

const keys = { main: process.env.JWT_PUBLIC_KEY }

function issue(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '15m' })
}

function check(token) {
  const { header } = jwt.decode(token, { complete: true })
  return jwt.verify(token, keys[header.kid], { algorithms: ['RS256'], audience: 'api' })
}

async function keyFor(header) {
  return db.query('SELECT pem FROM keys WHERE kid = $1', [header.kid])
}

module.exports = { issue, check, keyFor }
