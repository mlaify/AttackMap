const express = require('express')
const session = require('express-session')

const app = express()
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))

app.post('/login', async (req, res, next) => {
  const user = await users.check(req.body.email, req.body.password)
  if (!user) return res.status(401).end()
  req.session.regenerate((err) => {
    if (err) return next(err)
    req.session.userId = user.id
    res.redirect('/')
  })
})

app.post('/logout', (req, res) => {
  req.session.userId = null
  res.redirect('/')
})

module.exports = app
