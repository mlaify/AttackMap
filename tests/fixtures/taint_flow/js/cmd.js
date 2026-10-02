const express = require("express");
const child_process = require("child_process");

const app = express();
app.use(express.json());

app.post("/diag/ping", (req, res) => {
  const host = req.body.host; // taint: source
  child_process.exec(`ping -c 1 ${host}`, (err, stdout) => { // taint: sink
    res.send(err ? "unreachable" : stdout);
  });
});

module.exports = app;
