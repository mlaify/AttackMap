const crypto = require('crypto')
const express = require('express')
const partner = require('../partner-client')

const router = express.Router()
const PARTNER_REDIRECT_URIS = ['https://app.example.com/partner/callback']

router.get('/partner/start', (req, res) => {
  req.session.partnerState = crypto.randomBytes(32).toString('hex')
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.PARTNER_CLIENT_ID,
    redirect_uri: PARTNER_REDIRECT_URIS[0],
    state: req.session.partnerState,
  })
  res.redirect(`https://partner.example.com/authorize?${params}`)
})

router.get('/partner/callback', async (req, res) => {
  const redirect_uri = String(req.query.redirect_uri || '')
  if (!PARTNER_REDIRECT_URIS.includes(redirect_uri)) return res.status(400).end()
  if (req.query.state !== req.session.partnerState) return res.status(400).end()
  const tokens = await partner.exchange(req.query.code, redirect_uri)
  res.json({ ok: Boolean(tokens) })
})

module.exports = router
