package main

import (
	"net/http"
	"path/filepath"
)

const exportDir = "/srv/exports"

func downloadHandler(w http.ResponseWriter, r *http.Request) { // taint: route
	name := filepath.Base(r.URL.Query().Get("file"))
	http.ServeFile(w, r, filepath.Join(exportDir, name)) // taint: sink
}
