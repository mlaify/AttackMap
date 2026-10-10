// #242: one handler scopes its query to the caller, its sibling doesn't.
// Only the unscoped one may be flagged; the sibling's check must not leak.
const express = require('express');
const mongoose = require('mongoose');
const { requireAuth } = require('./middleware/auth');

const Order = mongoose.model('Order');
const Receipt = mongoose.model('Receipt');
const app = express();

app.get('/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
  res.json(order);
});

app.get('/receipts/:id', requireAuth, async (req, res) => {
  const receipt = await Receipt.findById(req.params.id);
  res.json(receipt);
});
