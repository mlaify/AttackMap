import { createRemoteJWKSet, jwtVerify } from 'jose'

const JWKS = createRemoteJWKSet(new URL(process.env.JWKS_URL!))

export async function currentUser(token: string) {
  const { payload } = await jwtVerify(token, JWKS, { issuer: 'https://id.example.com', audience: 'api' })
  return payload.sub
}
