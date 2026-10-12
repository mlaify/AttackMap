const jwt = require('jsonwebtoken')

function login(req, res) {
  const user = { id: 'demo', role: 'user' }
  const token = jwt.sign({ sub: user.id, role: user.role }, 'keyboard cat', { expiresIn: '1h' })
  res.json({ token })
}

module.exports = { login }
