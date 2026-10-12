const crypto = require('crypto')
const express = require('express')
const db = require('../db')

module.exports = (app) => {
  app.post('/webhooks/github', express.raw({ type: 'application/json' }), async (req, res) => {
    const payload = req.body
    const signature = req.get('X-Hub-Signature-256')
    const expected = 'sha256=' + crypto.createHmac('sha256', process.env.GH_SECRET).update(req.body).digest('hex')
    if (signature !== expected) {
      return res.status(401).end()
    }
    await db.query('insert into deploys(payload) values ($1)', [payload.toString()])
    res.status(204).end()
  })
}
