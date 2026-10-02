const express = require("express");
const multer = require("multer");
const path = require("path");
const AdmZip = require("adm-zip");

const app = express();
const upload = multer({ dest: "/tmp/uploads" });
const THEME_DIR = "/srv/themes";

app.post("/themes/import", upload.single("bundle"), (req, res) => { // taint: route
  const zip = new AdmZip(req.file.path);
  for (const entry of zip.getEntries()) {
    const target = path.resolve(THEME_DIR, entry.entryName);
    if (!target.startsWith(THEME_DIR + path.sep)) {
      return res.status(400).send("bad archive");
    }
    zip.extractEntryTo(entry, THEME_DIR, true, true); // taint: sink
  }
  res.json({ ok: true });
});
