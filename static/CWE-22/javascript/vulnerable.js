// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// Untrusted request input is used as a file path without validation, allowing directory traversal.
// Vulnerable sink: fs.readFile(path.join(__dirname, req.query.file))

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

app.get('/download', (req, res) => {
  const file = req.query.file;
  const filePath = path.join(__dirname, 'files', file);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('not found');
    res.send(data);
  });
});

app.listen(3000);
