// Remediation for CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// Fix: Resolve the requested path and verify it stays contained within the allowed base directory before reading.

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

const BASE_DIR = path.resolve(__dirname, 'files');

app.get('/download', (req, res) => {
  const file = req.query.file;
  const filePath = path.resolve(BASE_DIR, file);
  if (filePath !== BASE_DIR && !filePath.startsWith(BASE_DIR + path.sep)) {
    return res.status(400).send('invalid path');
  }
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.send(data);
  });
});

app.listen(3000);
