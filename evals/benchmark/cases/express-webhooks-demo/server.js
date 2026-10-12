const express = require('express')

const app = express()

require('./routes/payments')(app)
require('./routes/github')(app)
require('./routes/github-app')(app)
require('./routes/slack')(app)
require('./routes/stripe')(app)

app.listen(3000)
