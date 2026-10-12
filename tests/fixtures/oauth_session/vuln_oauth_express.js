const express = require('express')
const passport = require('passport')
const GitHubStrategy = require('passport-github2').Strategy

const router = express.Router()

router.get('/login', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.CLIENT_ID,
    redirect_uri: 'https://app.example.com/callback',
    scope: 'openid profile',
  })
  res.redirect(`https://id.example.com/authorize?${params}`)
})

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'https://app.example.com/auth/github/callback',
}, (accessToken, refreshToken, profile, done) => done(null, profile)))

function allowedRedirect(redirect_uri) {
  return redirect_uri.startsWith('https://app.example.com')
}

module.exports = { router, allowedRedirect }
