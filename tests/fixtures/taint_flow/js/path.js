const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const REPORT_DIR = "/srv/reports";

app.get("/reports/download", (req, res) => {
  const name = req.query.name; // taint: source
  const data = fs.readFileSync(path.join(REPORT_DIR, name)); // taint: sink
  res.type("application/pdf").send(data);
});

module.exports = app;
