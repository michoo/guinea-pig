// Remediation for CWE-798: Use of Hard-coded Credentials
// Fix: Load the JWT signing secret from an environment variable instead of hard-coding it in source.

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET_KEY = process.env.JWT_SECRET;
if (!SECRET_KEY) {
  throw new Error('JWT_SECRET environment variable is not set');
}

app.post('/login', (req, res) => {
  const username = req.body.username;
  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/verify', (req, res) => {
  const decoded = jwt.verify(req.query.token, SECRET_KEY);
  res.json(decoded);
});

app.listen(3000);
