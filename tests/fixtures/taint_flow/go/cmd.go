package main

import (
	"net/http"
	"os/exec"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host") // taint: source
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput() // taint: sink
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
