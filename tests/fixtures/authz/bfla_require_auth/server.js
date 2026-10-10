// #242: both admin routes require a login; only one requires the admin role.
const express = require('express');
const mongoose = require('mongoose');
const { requireAuth, requireRole } = require('./middleware/auth');

const User = mongoose.model('User');
const Session = mongoose.model('Session');
const app = express();

app.delete('/admin/users/:id', requireAuth, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

app.delete('/admin/sessions/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await Session.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});
