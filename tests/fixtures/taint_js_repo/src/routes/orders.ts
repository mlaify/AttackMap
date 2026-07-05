import express from "express";
import { placeOrder } from "../services/orders";

const app = express();

app.post("/orders", async (req, res) => {
  const result = await placeOrder(req.body.orderId);
  res.json(result);
});
