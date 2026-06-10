// CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Untrusted request input is interpolated into a shell command executed by the OS.
// Vulnerable sink: child_process.exec(`ping -c 1 ${req.query.host}`)

const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr);
    res.send(stdout);
  });
});

app.listen(3000);
