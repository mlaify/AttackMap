const express = require('express')
const MessageValidator = require('sns-validator')
const db = require('./db')
const validator = new MessageValidator()
const app = express()
app.use(express.json())

app.post('/webhooks/sns', (req, res) => {
  validator.validate(req.body, (err, message) => {
    if (err) return res.status(403).end()
    db.bounces.insert(JSON.parse(message.Message))
    res.end()
  })
})
