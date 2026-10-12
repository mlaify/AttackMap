const express = require('express')
const crypto = require('crypto')
const db = require('./db')
const app = express()

app.post('/webhooks/slack', express.raw({ type: '*/*' }), (req, res) => {
  const ts = req.get('X-Slack-Request-Timestamp')
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return res.status(400).end()
  const sig = Buffer.from(req.get('X-Slack-Signature') || '')
  const mine = Buffer.from('v0=' + crypto.createHmac('sha256', process.env.SLACK_SECRET).update(`v0:${ts}:${req.body}`).digest('hex'))
  if (sig.length !== mine.length || !crypto.timingSafeEqual(sig, mine)) return res.status(401).end()
  db.commands.insert(JSON.parse(req.body))
  res.end()
})
