// Test fixture (#242): safe binders.
router.post('/accounts', async (req, res) => {
  await Account.update(req.body, { where: { id: req.user.id }, fields: ['name', 'bio'] });
  await Account.create(req.body, {
    fields: ['name'],
  });
  res.sendStatus(204);
});

router.put('/users/:id', async (req, res) => {
  const { name, bio } = req.body;
  await User.findByIdAndUpdate(req.params.id, { name, bio });
  res.sendStatus(204);
});
