const express = require("express");
const path = require("path");

const app = express();
const EXPORT_DIR = "/srv/exports";

app.get("/exports/download", (req, res) => { // taint: route
  const name = req.query.file;
  res.sendFile(path.join(EXPORT_DIR, name)); // taint: sink
});
