// Remediation for CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
// Fix: The recursive merge skips dangerous keys (__proto__, constructor, prototype) and uses Object.create(null) targets.

const express = require('express');

const app = express();
app.use(express.json());

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function merge(target, source) {
  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (FORBIDDEN_KEYS.has(key)) continue;
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
