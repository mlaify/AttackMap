const express = require('express')
const users = require('../users')

const router = express.Router()

router.post('/staff/login', async (req, res, next) => {
  const user = await users.checkStaff(req.body.email, req.body.password)
  if (!user) return res.status(401).end()
  req.session.regenerate((err) => {
    if (err) return next(err)
    req.session.userId = user.id
    res.redirect('/staff')
  })
})

module.exports = router
