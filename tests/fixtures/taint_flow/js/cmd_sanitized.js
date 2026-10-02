const express = require("express");
const child_process = require("child_process");

const app = express();
app.use(express.json());
const ALLOWED_TARGETS = new Set(["db01.internal", "db02.internal"]);

app.post("/diag/ping", (req, res) => {
  const host = req.body.host; // taint: source
  if (!ALLOWED_TARGETS.has(host)) {
    return res.status(400).end();
  }
  child_process.exec(`ping -c 1 ${host}`, (err, stdout) => { // taint: sink
    res.send(err ? "unreachable" : stdout);
  });
});

module.exports = app;
