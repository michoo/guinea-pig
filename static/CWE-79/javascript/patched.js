// Remediation for CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
// Fix: HTML-encode untrusted input before reflecting it into the response so it cannot be interpreted as markup.

const express = require('express');

const app = express();

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

app.get('/greet', (req, res) => {
  const name = escapeHtml(req.query.name);
  res.send(`<html><body><h1>Hello ${name}</h1></body></html>`);
});

app.listen(3000);
