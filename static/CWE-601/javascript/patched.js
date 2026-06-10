// Remediation for CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
// Fix: Only redirect to paths/hosts present in a server-side allowlist, rejecting any other target.

const express = require('express');

const app = express();

const ALLOWED_REDIRECTS = new Set(['/home', '/dashboard', '/login']);

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  if (!ALLOWED_REDIRECTS.has(url)) {
    return res.status(400).send('invalid redirect target');
  }
  res.redirect(url);
});

app.listen(3000);
