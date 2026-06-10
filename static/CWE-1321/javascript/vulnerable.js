// CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
// A recursive merge copies attacker-controlled keys (including __proto__) into a target object.
// Vulnerable sink: target[key] = merge(target[key], source[key]) without key filtering

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
