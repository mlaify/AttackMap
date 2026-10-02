const express = require("express");
const { spawn } = require("child_process");

const app = express();

app.get("/archive", (req, res) => { // taint: route
  const dir = req.query.dir;
  const child = spawn("tar", ["czf", "-", "--", dir]); // taint: sink
  child.stdout.pipe(res);
});
