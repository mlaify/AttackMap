const express = require("express");
const axios = require("axios");

const app = express();
const ALLOWED_HOSTS = ["api.partner.example", "cdn.partner.example"];

app.get("/fetch", async (req, res) => {
  const target = req.query.url; // taint: source
  const host = new URL(target).hostname;
  if (!ALLOWED_HOSTS.includes(host)) {
    return res.status(400).send("host not allowed");
  }
  const resp = await axios.get(target, { timeout: 3000 }); // taint: sink
  res.send(resp.data);
});

module.exports = app;
