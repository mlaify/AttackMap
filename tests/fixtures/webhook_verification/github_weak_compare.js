const express = require('express')
const crypto = require('crypto')
const db = require('./db')
const app = express()

app.post('/webhooks/github', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.get('X-Hub-Signature-256')
  const expected = 'sha256=' + crypto.createHmac('sha256', process.env.GH_SECRET).update(req.body).digest('hex')
  if (signature !== expected) {
    return res.status(401).end()
  }
  db.deploys.create(JSON.parse(req.body))
  res.status(204).end()
})
