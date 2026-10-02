const express = require("express");
const axios = require("axios");

const app = express();

app.get("/fetch", async (req, res) => {
  const target = req.query.url; // taint: source
  const resp = await axios.get(target, { timeout: 3000 }); // taint: sink
  res.send(resp.data);
});

module.exports = app;
