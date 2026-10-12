const express = require('express')
const session = require('express-session')

const app = express()
app.use(express.urlencoded({ extended: false }))
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false }))

app.use(require('./routes/login'))
app.use(require('./routes/staff-login'))
app.use(require('./routes/sso'))
app.use(require('./routes/partner-sso'))

app.listen(3000)
