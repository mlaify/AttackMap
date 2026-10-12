const express = require('express')
const Stripe = require('stripe')
const db = require('./db')
const stripe = Stripe(process.env.STRIPE_KEY)
const app = express()

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature']
  let event
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET)
  } catch (err) {
    return res.status(400).send('bad signature')
  }
  db.orders.markPaid(event.data.object.id)
  res.json({ received: true })
})
