const express = require('express')
const Stripe = require('stripe')
const db = require('../db')

const stripe = Stripe(process.env.STRIPE_KEY)

module.exports = (app) => {
  app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    let event
    try {
      event = stripe.webhooks.constructEvent(req.body, req.get('Stripe-Signature'), process.env.STRIPE_WEBHOOK_SECRET)
    } catch (err) {
      return res.status(400).send('bad signature')
    }
    await db.query('update orders set paid = true where id = $1', [event.data.object.metadata.order])
    res.json({ received: true })
  })
}
