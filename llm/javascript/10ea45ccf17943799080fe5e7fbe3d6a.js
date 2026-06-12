const express = require('express');

const app = express();
app.use(express.json());

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post('/config', (req, res) => {
  const config = {};
  merge(config, req.body);
  res.json(config);
});

app.listen(3000);
