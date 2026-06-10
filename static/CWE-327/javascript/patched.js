// Remediation for CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// Fix: Hash passwords with bcrypt (a strong, salted, adaptive algorithm) instead of MD5.

const express = require('express');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const SALT_ROUNDS = 12;

function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

app.post('/register', async (req, res) => {
  const password = req.body.password;
  const hashed = await hashPassword(password);
  res.json({ passwordHash: hashed });
});

app.listen(3000);
