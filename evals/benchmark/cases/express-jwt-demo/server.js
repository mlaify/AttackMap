const express = require('express')
const session = require('./session')
const partner = require('./partner')
const profile = require('./profile')
const admin = require('./admin')

const app = express()
app.use(express.json())

app.get('/login', session.login)
app.get('/partner/feed', partner.requirePartner, (req, res) => res.json({ feed: [] }))
app.get('/me', profile.me)
app.get('/admin/stats', admin.requireAdmin, (req, res) => res.json({ ok: true }))

app.listen(3000)
