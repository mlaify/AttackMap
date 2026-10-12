package auth

import (
	"net/http"
	"net/url"
	"strings"
)

func Login(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://app.example.com/callback")
	http.Redirect(w, r, "https://id.example.com/authorize?"+q.Encode(), http.StatusFound)
}

func RedirectAllowed(redirectURI string) bool {
	return strings.HasPrefix(redirectURI, "https://app.example.com")
}
