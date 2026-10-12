import { decodeJwt, SignJWT } from 'jose'

const secret = new TextEncoder().encode('dev-secret')

export async function issue(sub: string) {
  return new SignJWT({ sub }).setProtectedHeader({ alg: 'HS256' }).sign(secret)
}

export function currentUser(token: string) {
  return decodeJwt(token).sub
}
