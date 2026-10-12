import * as AuthSession from 'expo-auth-session'

const CLIENT_ID = 'spa-client'

export function loginImplicit() {
  window.location.href =
    `https://id.example.com/authorize?response_type=token&client_id=${CLIENT_ID}&state=${crypto.randomUUID()}`
}

export function loginCode() {
  const state = crypto.randomUUID()
  window.location.assign(`https://id.example.com/authorize?response_type=code&client_id=${CLIENT_ID}&state=${state}`)
}

export const request = new AuthSession.AuthRequest({ clientId: CLIENT_ID, usePKCE: false, redirectUri: 'app://cb' })
