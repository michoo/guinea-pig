// Remediation for CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Fix: Use execFile with an argument array (no shell) and validate the host so input cannot be interpreted as shell syntax.

const express = require('express');
const { execFile } = require('child_process');

const app = express();

const HOST_PATTERN = /^[a-zA-Z0-9.-]+$/;

app.get('/ping', (req, res) => {
  const host = req.query.host;
  if (typeof host !== 'string' || !HOST_PATTERN.test(host)) {
    return res.status(400).send('invalid host');
  }
  execFile('ping', ['-c', '1', host], (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr);
    res.send(stdout);
  });
});

app.listen(3000);
