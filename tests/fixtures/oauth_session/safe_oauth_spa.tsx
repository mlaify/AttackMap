import * as AuthSession from 'expo-auth-session'

const CLIENT_ID = 'spa-client'

export async function loginCode(challenge: string) {
  const state = crypto.randomUUID()
  window.location.assign(
    `https://id.example.com/authorize?response_type=code&client_id=${CLIENT_ID}&state=${state}` +
      `&code_challenge=${challenge}&code_challenge_method=S256`,
  )
}

export const request = new AuthSession.AuthRequest({ clientId: CLIENT_ID, usePKCE: true, redirectUri: 'app://cb' })
