const express = require('express')
const { verifyGithub } = require('./helpers/verify')
const db = require('./db')
const app = express()

app.post('/webhooks/github', express.raw({ type: 'application/json' }), (req, res) => {
  if (!verifyGithub(req)) return res.status(401).end()
  db.deploys.create(JSON.parse(req.body))
  res.status(204).end()
})
