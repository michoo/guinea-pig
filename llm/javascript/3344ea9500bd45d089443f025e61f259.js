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
