package main

import (
	"encoding/json"
	"net/http"
	"regexp"
)

func searchHandler(w http.ResponseWriter, r *http.Request) { // taint: route
	q := r.URL.Query().Get("q")
	re, err := regexp.Compile(q) // taint: sink
	if err != nil {
		http.Error(w, "bad pattern", http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(filterLogs(re))
}
