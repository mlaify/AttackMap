const express = require("express");
const xpath = require("xpath");
const { DOMParser } = require("@xmldom/xmldom");
const fs = require("fs");

const app = express();
const catalog = new DOMParser().parseFromString(fs.readFileSync("catalog.xml", "utf8"));

app.get("/catalog/item", (req, res) => { // taint: route
  const sku = req.query.sku;
  const nodes = xpath.select(`//item[@sku='${sku}']/price/text()`, catalog); // taint: sink
  res.json({ price: nodes.length ? nodes[0].nodeValue : null });
});
