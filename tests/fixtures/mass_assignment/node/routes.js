// Test fixture (#242): deliberately vulnerable.
router.put('/users/:id', async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});

router.patch('/users/:id/profile', async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { $set: req.body });
  res.sendStatus(204);
});

router.post('/accounts', async (req, res) => {
  await Account.update(req.body, { where: { id: req.user.id } });
  res.sendStatus(204);
});
