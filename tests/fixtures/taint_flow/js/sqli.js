const express = require("express");
const { Pool } = require("pg");

const app = express();
const pool = new Pool();

app.get("/orders/search", async (req, res) => {
  const term = req.query.q; // taint: source
  const sql = "SELECT id, sku FROM orders WHERE sku LIKE '%" + term + "%'";
  const result = await pool.query(sql); // taint: sink
  res.json(result.rows);
});

module.exports = app;
