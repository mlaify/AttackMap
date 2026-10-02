package main

import "net/http"

func tagHandler(w http.ResponseWriter, r *http.Request) { // taint: route
	tag := r.URL.Query().Get("tag")
	w.Header().Set("X-Request-Tag", tag) // taint: sink
	w.WriteHeader(http.StatusNoContent)
}
