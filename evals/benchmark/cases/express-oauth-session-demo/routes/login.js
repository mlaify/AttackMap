const express = require('express')
const users = require('../users')

const router = express.Router()

router.post('/login', async (req, res) => {
  const user = await users.check(req.body.email, req.body.password)
  if (!user) return res.status(401).end()
  req.session.userId = user.id
  res.redirect('/')
})

module.exports = router
