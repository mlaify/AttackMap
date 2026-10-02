const express = require("express");
const escapeStringRegexp = require("escape-string-regexp");

const app = express();

app.get("/logs/search", (req, res) => { // taint: route
  const q = escapeStringRegexp(req.query.q);
  const matcher = new RegExp(q, "i"); // taint: sink
  res.json({ hits: readLogs().filter((line) => matcher.test(line)) });
});
