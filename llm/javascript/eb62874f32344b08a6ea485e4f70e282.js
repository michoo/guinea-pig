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
