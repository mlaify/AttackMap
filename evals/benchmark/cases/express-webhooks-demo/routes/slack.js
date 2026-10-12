const crypto = require('crypto')
const express = require('express')
const db = require('../db')

module.exports = (app) => {
  app.post('/webhooks/slack', express.raw({ type: '*/*' }), async (req, res) => {
    const ts = req.get('X-Slack-Request-Timestamp')
    const signature = Buffer.from(req.get('X-Slack-Signature') || '')
    const base = `v0:${ts}:${req.body}`
    const expected = Buffer.from('v0=' + crypto.createHmac('sha256', process.env.SLACK_SECRET).update(base).digest('hex'))
    if (signature.length !== expected.length || !crypto.timingSafeEqual(signature, expected)) {
      return res.status(401).end()
    }
    await db.query('insert into commands(payload) values ($1)', [req.body.toString()])
    res.end()
  })
}
