const express = require("express");
const { execFile } = require("child_process");

const app = express();

app.get("/thumbnails", (req, res) => { // taint: route
  const file = req.query.file;
  execFile("convert", [file, "-resize", "128x128", "/tmp/thumb.png"], (err) => { // taint: sink
    res.sendStatus(err ? 500 : 204);
  });
});
