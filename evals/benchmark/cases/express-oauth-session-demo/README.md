# express-oauth-session-demo

Benchmark case for OAuth client and session checks (#243 part 2). Deliberately
vulnerable; don't copy it.

- `server.js` signs sessions with express-session's documented example secret.
- `routes/login.js` stores the user in the session without regenerating it (fixation).
- `routes/sso.js` sends the authorization request without `state`, and its callback accepts any
  redirect URI that starts with the app's origin.
- Clean twins: `routes/staff-login.js` regenerates the session before storing the
  user; `routes/partner-sso.js` sends `state` and matches redirect URIs exactly.
