package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("q") // taint: source
	query := "SELECT id, sku FROM orders WHERE sku LIKE '%" + term + "%'"
	rows, err := db.Query(query) // taint: sink
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var skus []string
	for rows.Next() {
		var id int
		var sku string
		rows.Scan(&id, &sku)
		skus = append(skus, sku)
	}
	json.NewEncoder(w).Encode(skus)
}

func main() {
	http.HandleFunc("/orders/search", searchHandler)
	http.ListenAndServe(":8080", nil)
}
