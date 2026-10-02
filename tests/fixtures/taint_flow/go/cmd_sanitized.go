package main

import (
	"net/http"
	"os/exec"
	"regexp"
)

var hostPattern = regexp.MustCompile(`^[a-z0-9.-]+$`)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host") // taint: source
	if !hostPattern.MatchString(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("ping", "-c", "1", host).CombinedOutput() // taint: sink
	if err != nil {
		http.Error(w, "unreachable", http.StatusBadGateway)
		return
	}
	w.Write(out)
}

func main() {
	http.HandleFunc("/diag/ping", pingHandler)
	http.ListenAndServe(":8080", nil)
}
