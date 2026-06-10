// CWE-798: Use of Hard-coded Credentials
// A hard-coded secret key is used to sign and verify JWT tokens.
// Vulnerable sink: jwt.sign(payload, 'hardcoded-secret-key')

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET_KEY = 'super-secret-hardcoded-key-12345';

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
