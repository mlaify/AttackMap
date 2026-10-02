const express = require("express");

const app = express();

app.get("/logs/search", (req, res) => { // taint: route
  const q = req.query.q;
  const matcher = new RegExp(q, "i"); // taint: sink
  res.json({ hits: readLogs().filter((line) => matcher.test(line)) });
});
