const fs = require('fs')
const path = require('path')

function partnerKey(header) {
  return fs.readFileSync(path.join(__dirname, 'keys', `${header.kid}.pem`))
}

const ADMIN_KEYS = { 2026: process.env.ADMIN_PUBLIC_KEY }

function adminKey(header) {
  return ADMIN_KEYS[header.kid]
}

module.exports = { partnerKey, adminKey }
