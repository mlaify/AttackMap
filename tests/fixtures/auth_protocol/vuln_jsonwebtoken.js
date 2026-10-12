const jwt = require('jsonwebtoken')
const fs = require('fs')

function issue(user) {
  return jwt.sign({ sub: user.id, role: user.role }, 'changeme')
}

function check(token) {
  return jwt.verify(token, publicKey)
}

function lenient(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true })
}

function keyFor(header) {
  return fs.readFileSync(`keys/${header.kid}.pem`)
}

async function remoteKey(header) {
  return fetch(header.jku).then((r) => r.json())
}

module.exports = { issue, check, lenient, keyFor, remoteKey }
