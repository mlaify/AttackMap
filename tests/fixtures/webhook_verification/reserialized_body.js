const express = require('express')
const crypto = require('crypto')
const db = require('./db')
const app = express()
app.use(express.json())

app.post('/webhooks/github', (req, res) => {
  const sig = Buffer.from(req.get('X-Hub-Signature-256') || '')
  const mine = Buffer.from('sha256=' + crypto.createHmac('sha256', process.env.GH_SECRET).update(JSON.stringify(req.body)).digest('hex'))
  if (sig.length !== mine.length || !crypto.timingSafeEqual(sig, mine)) return res.status(401).end()
  db.deploys.create(req.body)
  res.end()
})
