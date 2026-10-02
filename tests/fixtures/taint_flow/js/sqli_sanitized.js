const express = require("express");
const { Pool } = require("pg");

const app = express();
const pool = new Pool();

app.get("/orders/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10); // taint: source
  const sql = `SELECT id, sku FROM orders WHERE id = ${id}`;
  const result = await pool.query(sql); // taint: sink
  res.json(result.rows[0]);
});

module.exports = app;
