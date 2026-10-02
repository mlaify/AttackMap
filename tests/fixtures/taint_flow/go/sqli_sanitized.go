package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

var db *sql.DB

func orderHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id")) // taint: source
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	query := fmt.Sprintf("SELECT sku FROM orders WHERE id = %d", id)
	var sku string
	db.QueryRow(query).Scan(&sku) // taint: sink
	fmt.Fprint(w, sku)
}

func main() {
	http.HandleFunc("/orders/lookup", orderHandler)
	http.ListenAndServe(":8080", nil)
}
