const express = require('express')
const cookieSession = require('cookie-session')

const app = express()
app.use(cookieSession({ name: 'session', keys: ['key1'] }))

app.post('/login', async (req, res) => {
  req.session.user = await users.check(req.body.email, req.body.password)
  res.redirect('/')
})

module.exports = app
