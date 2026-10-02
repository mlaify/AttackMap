package main

import (
	"io"
	"net/http"
)

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url") // taint: source
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
