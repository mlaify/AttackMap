const express = require("express");

const app = express();
app.use(express.json());

app.post("/pricing/preview", (req, res) => { // taint: route
  const formula = req.body.formula;
  const price = new Function("qty", "unit", "return " + formula); // taint: sink
  res.json({ total: price(req.body.qty, 9.99) });
});
