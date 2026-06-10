// CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
// Math.random() is used to generate a security-sensitive password reset token.
// Vulnerable sink: Math.random().toString(36) used as a token

const express = require('express');

const app = express();

function generateResetToken() {
  let token = '';
  for (let i = 0; i < 4; i++) {
    token += Math.random().toString(36).substring(2);
  }
  return token;
}

app.post('/reset-password', (req, res) => {
  const token = generateResetToken();
  res.json({ resetToken: token });
});

app.listen(3000);
