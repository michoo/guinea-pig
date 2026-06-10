// CWE-94: Improper Control of Generation of Code ('Code Injection')
// Untrusted request input is passed directly to eval() and executed as code.
// Vulnerable sink: eval(req.query.expr)

const express = require('express');

const app = express();

app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  const result = eval(expr);
  res.send(String(result));
});

app.listen(3000);
