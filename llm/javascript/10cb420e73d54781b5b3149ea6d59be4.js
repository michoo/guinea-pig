const express = require('express');

const app = express();

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

app.listen(3000);
