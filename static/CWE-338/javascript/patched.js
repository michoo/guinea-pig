// Remediation for CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
// Fix: Generate the reset token with crypto.randomBytes instead of the predictable Math.random().

const express = require('express');
const crypto = require('crypto');

const app = express();

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.post('/reset-password', (req, res) => {
  const token = generateResetToken();
  res.json({ resetToken: token });
});

app.listen(3000);
