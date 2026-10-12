const express = require('express')
const db = require('../db')

module.exports = (app) => {
  // No signature check: anyone can post a "payment succeeded" event.
  app.post('/webhook/payments', express.json(), async (req, res) => {
    const event = req.body
    if (event.type === 'payment.succeeded') {
      await db.query('update invoices set paid = true where id = $1', [event.data.invoice])
    }
    res.sendStatus(200)
  })
}
