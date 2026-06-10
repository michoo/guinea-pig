// Remediation for CWE-502: Deserialization of Untrusted Data
// Fix: Parse the untrusted input with JSON.parse instead of node-serialize, which cannot execute embedded code.

const express = require('express');

const app = express();
app.use(express.json());

app.post('/load', (req, res) => {
  const data = req.body.data;
  let obj;
  try {
    obj = typeof data === 'string' ? JSON.parse(data) : data;
  } catch (err) {
    return res.status(400).json({ error: 'invalid data' });
  }
  res.json({ loaded: obj });
});

app.listen(3000);
