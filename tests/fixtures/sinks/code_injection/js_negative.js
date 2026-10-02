const express = require("express");

const app = express();
app.use(express.json());

app.post("/jobs/remind", (req, res) => { // taint: route
  const jobId = req.body.jobId;
  setTimeout(() => sendReminder(jobId), 60000); // taint: sink
  res.json({ scheduled: true });
});
