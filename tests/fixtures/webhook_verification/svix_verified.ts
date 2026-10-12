import express from 'express'
import { Webhook } from 'svix'
import { db } from './db'

const app = express()

app.post('/webhooks/clerk', express.raw({ type: 'application/json' }), (req, res) => {
  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!)
  const evt = wh.verify(req.body, req.headers as Record<string, string>) as { type: string; data: { id: string } }
  db.users.upsert(evt.data)
  res.sendStatus(204)
})
