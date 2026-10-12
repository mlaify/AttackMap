package auth

import (
	"net/http"
	"net/url"
)

func Login(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://app.example.com/callback")
	q.Set("state", newState(w))
	http.Redirect(w, r, "https://id.example.com/authorize?"+q.Encode(), http.StatusFound)
}

func RedirectAllowed(redirectURI string) bool {
	return redirectURI == "https://app.example.com/callback"
}
