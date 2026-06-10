// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// Passwords are hashed with the broken MD5 algorithm.
// Vulnerable sink: crypto.createHash('md5')

const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

app.post('/register', (req, res) => {
  const password = req.body.password;
  const hashed = hashPassword(password);
  res.json({ passwordHash: hashed });
});

app.listen(3000);
