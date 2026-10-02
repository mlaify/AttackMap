package main

import (
	"io"
	"net/http"
	"net/url"
)

var allowedHosts = map[string]bool{"api.partner.example": true}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url") // taint: source
	u, err := url.Parse(target)
	if err != nil || !allowedHosts[u.Hostname()] {
		http.Error(w, "host not allowed", http.StatusBadRequest)
		return
	}
	resp, err := http.Get(target) // taint: sink
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/fetch", fetchHandler)
	http.ListenAndServe(":8080", nil)
}
