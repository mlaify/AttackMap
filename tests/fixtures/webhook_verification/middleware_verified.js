const express = require('express')
const crypto = require('crypto')
const db = require('./db')
const router = express.Router()

function checkSignature(req, res, next) {
  const sig = Buffer.from(req.get('X-Signature') || '')
  const mine = Buffer.from(crypto.createHmac('sha256', process.env.HOOK_SECRET).update(req.body).digest('hex'))
  if (sig.length !== mine.length || !crypto.timingSafeEqual(sig, mine)) return res.status(401).end()
  next()
}

router.use(checkSignature)

router.post('/webhook/partner', (req, res) => {
  db.events.insert(JSON.parse(req.body))
  res.end()
})

module.exports = router
