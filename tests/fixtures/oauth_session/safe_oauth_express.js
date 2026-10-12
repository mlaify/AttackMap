const crypto = require('crypto')
const express = require('express')
const passport = require('passport')
const GitHubStrategy = require('passport-github2').Strategy

const router = express.Router()
const ALLOWED_REDIRECT_URIS = ['https://app.example.com/callback']

router.get('/login', (req, res) => {
  req.session.oauthState = crypto.randomBytes(32).toString('hex')
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.CLIENT_ID,
    redirect_uri: 'https://app.example.com/callback',
    state: req.session.oauthState,
  })
  res.redirect(`https://id.example.com/authorize?${params}`)
})

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'https://app.example.com/auth/github/callback',
  state: true,
}, (accessToken, refreshToken, profile, done) => done(null, profile)))

function allowedRedirect(redirect_uri) {
  return ALLOWED_REDIRECT_URIS.includes(redirect_uri)
}

module.exports = { router, allowedRedirect }
