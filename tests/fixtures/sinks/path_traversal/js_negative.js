const express = require("express");

const app = express();
const EXPORT_DIR = "/srv/exports";

app.get("/exports/download", (req, res) => { // taint: route
  const name = req.query.file;
  res.sendFile(name, { root: EXPORT_DIR }); // taint: sink
});
