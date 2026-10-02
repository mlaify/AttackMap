const express = require("express");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

const app = express();
const DOCS_DIR = path.join(__dirname, "docs");

// Raw doc download: the query value is joined into a filesystem path unchecked.
app.get("/docs/raw", (req, res) => {
  const file = req.query.file;
  const body = fs.readFileSync(path.join(DOCS_DIR, file), "utf8");
  res.type("text/plain").send(body);
});

// Rendered doc view: reduced to a basename before it touches the filesystem.
app.get("/docs/view", (req, res) => {
  const file = path.basename(req.query.file);
  const body = fs.readFileSync(path.join(DOCS_DIR, file), "utf8");
  res.render("doc", { body });
});

// Link preview: the caller chooses the URL the server fetches.
app.get("/preview", async (req, res) => {
  const target = req.query.url;
  const resp = await axios.get(target, { timeout: 3000 });
  res.json({ title: resp.data.title });
});

// Service status: fixed upstream host, only the path segment is caller-controlled.
app.get("/status/:service", async (req, res) => {
  const service = encodeURIComponent(req.params.service);
  const resp = await axios.get(`https://status.example.com/api/${service}`);
  res.json(resp.data);
});

app.listen(3000);
