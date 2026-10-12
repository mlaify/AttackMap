# express-jwt-demo

Benchmark case for JWT verification (#243). Deliberately vulnerable; don't copy it.

- `session.js` issues tokens with a short hard-coded HMAC secret.
- `partner.js` verifies partner tokens with a public key and no `algorithms` list
  (on jsonwebtoken < 9 an HS256 token signed with the public key as the secret passes;
  `package.json` pins 9.x, which blocks that swap, but nothing in the code pins the algorithm).
- `profile.js` reads the caller from `jwt.decode`, which never checks the signature.
- `keys.js` builds a key file path from the unverified header's `kid`.
- `admin.js` is the clean twin: a key map lookup and a pinned `RS256` verify.
