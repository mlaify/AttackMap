const express = require('express')
const session = require('express-session')

const app = express()
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false }))

app.post('/login', async (req, res) => {
  const user = await users.check(req.body.email, req.body.password)
  if (!user) return res.status(401).end()
  req.session.userId = user.id
  res.redirect('/')
})

module.exports = app
