// #242: every route sits behind router.use(requireAuth) and the handler reads
// req.user, yet the invoice is loaded by a client-supplied id with no
// ownership check — the classic authenticated IDOR.
const express = require('express');
const mongoose = require('mongoose');
const { requireAuth } = require('../middleware/auth');

const Invoice = mongoose.model('Invoice');
const router = express.Router();
router.use(requireAuth);

router.get('/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  console.log('invoice viewed by', req.user.email);
  res.json(invoice);
});

module.exports = router;
