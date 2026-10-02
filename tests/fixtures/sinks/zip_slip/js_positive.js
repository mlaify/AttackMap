const express = require("express");
const multer = require("multer");
const AdmZip = require("adm-zip");

const app = express();
const upload = multer({ dest: "/tmp/uploads" });

app.post("/themes/import", upload.single("bundle"), (req, res) => { // taint: route
  const zip = new AdmZip(req.file.path);
  zip.extractAllTo("/srv/themes", true); // taint: sink
  res.json({ ok: true });
});
