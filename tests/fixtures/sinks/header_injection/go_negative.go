package main

import (
	"net/http"
	"net/url"
)

func tagHandler(w http.ResponseWriter, r *http.Request) { // taint: route
	tag := url.QueryEscape(r.URL.Query().Get("tag"))
	w.Header().Set("X-Request-Tag", tag) // taint: sink
	w.WriteHeader(http.StatusNoContent)
}
