const crypto = require('crypto')

function verifyGithub(req) {
  const sig = Buffer.from(req.get('X-Hub-Signature-256') || '')
  const mine = Buffer.from('sha256=' + crypto.createHmac('sha256', process.env.GH_SECRET).update(req.body).digest('hex'))
  return sig.length === mine.length && crypto.timingSafeEqual(sig, mine)
}

module.exports = { verifyGithub }
