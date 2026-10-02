package main

import (
	"net/http"
	"os"
	"path/filepath"
)

const reportDir = "/srv/reports"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name")) // taint: source
	data, err := os.ReadFile(filepath.Join(reportDir, name)) // taint: sink
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func main() {
	http.HandleFunc("/reports/download", downloadHandler)
	http.ListenAndServe(":8080", nil)
}
