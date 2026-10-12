const express = require('express')
const sso = require('../sso-client')

const router = express.Router()

router.get('/sso/start', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.SSO_CLIENT_ID,
    redirect_uri: 'https://app.example.com/sso/callback',
  })
  res.redirect(`https://sso.example.com/authorize?${params}`)
})

router.get('/sso/callback', async (req, res) => {
  const redirect_uri = String(req.query.redirect_uri || '')
  if (!redirect_uri.startsWith('https://app.example.com')) return res.status(400).end()
  const tokens = await sso.exchange(req.query.code, redirect_uri)
  res.json({ ok: Boolean(tokens) })
})

module.exports = router
