// CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
// Untrusted request input is reflected into an HTML response without escaping.
// Vulnerable sink: res.send(`<h1>Hello ${req.query.name}</h1>`)

const express = require('express');

const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send(`<html><body><h1>Hello ${name}</h1></body></html>`);
});

app.listen(3000);
