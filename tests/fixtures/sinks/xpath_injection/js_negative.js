const express = require("express");
const xpath = require("xpath");
const { DOMParser } = require("@xmldom/xmldom");
const fs = require("fs");

const app = express();
const catalog = new DOMParser().parseFromString(fs.readFileSync("catalog.xml", "utf8"));

app.get("/catalog/items", (req, res) => { // taint: route
  const limit = Number(req.query.limit);
  const nodes = xpath.select("//item/price/text()", catalog); // taint: sink
  res.json({ prices: nodes.slice(0, limit).map((n) => n.nodeValue) });
});
