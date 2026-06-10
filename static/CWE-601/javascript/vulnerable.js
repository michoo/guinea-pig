// CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
// Untrusted request input is used as the redirect target without validation.
// Vulnerable sink: res.redirect(req.query.url)

const express = require('express');

const app = express();

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

app.listen(3000);
