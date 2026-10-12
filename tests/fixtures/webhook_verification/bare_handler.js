const express = require('express')
const db = require('./db')
const app = express()
app.use(express.json())

app.post('/webhook/payments', async (req, res) => {
  const event = req.body
  if (event.type === 'payment.succeeded') {
    await db.invoices.markPaid(event.data.invoice)
  }
  res.sendStatus(200)
})
