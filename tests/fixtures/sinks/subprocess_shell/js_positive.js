const express = require("express");
const { exec } = require("child_process");

const app = express();

app.get("/thumbnails", (req, res) => { // taint: route
  const file = req.query.file;
  exec("convert " + file + " -resize 128x128 /tmp/thumb.png", (err) => { // taint: sink
    res.sendStatus(err ? 500 : 204);
  });
});
