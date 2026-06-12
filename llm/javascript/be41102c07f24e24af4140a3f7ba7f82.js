const express = require('express');
const serialize = require('node-serialize');

const app = express();
app.use(express.json());

app.post('/load', (req, res) => {
  const data = req.body.data;
  const obj = serialize.unserialize(data);
  res.json({ loaded: obj });
});

app.listen(3000);
