package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/webhooks/shopify", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte(os.Getenv("SHOPIFY_SECRET")))
		mac.Write(body)
		expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if r.Header.Get("X-Shopify-Hmac-Sha256") != expected {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		saveOrder(body)
	})
	http.ListenAndServe(":8080", nil)
}
