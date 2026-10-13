const crypto = require('crypto')
const express = require('express')
const db = require('../db')

module.exports = (app) => {
  app.post('/webhooks/github-app', express.raw({ type: 'application/json' }), async (req, res) => {
    const payload = req.body
    const signature = Buffer.from(req.get('X-Hub-Signature-256') || '')
    const expected = Buffer.from('sha256=' + crypto.createHmac('sha256', process.env.GH_APP_SECRET).update(req.body).digest('hex'))
    if (signature.length !== expected.length || !crypto.timingSafeEqual(signature, expected)) {
      return res.status(401).end()
    }
    await db.query('insert into installs(payload) values ($1)', [payload.toString()])
    res.status(204).end()
  })
}
