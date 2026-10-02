const express = require("express");

const app = express();

app.get("/exports/csv", (req, res) => { // taint: route
  const name = req.query.name || "export";
  res.setHeader("Content-Disposition", `attachment; filename=${name}.csv`); // taint: sink
  res.send(buildCsv());
});
