// Remediation for CWE-94: Improper Control of Generation of Code ('Code Injection')
// Fix: Replace eval() with a hand-written arithmetic evaluator so no untrusted input is ever executed as code.

const express = require('express');

const app = express();

// Safe recursive-descent evaluator for + - * / and parentheses over numeric literals.
function safeCalc(expr) {
  const tokens = String(expr).match(/\d+(\.\d+)?|[+\-*/()]/g) || [];
  let pos = 0;
  const peek = () => tokens[pos];
  const parseExpr = () => {
    let v = parseTerm();
    while (peek() === '+' || peek() === '-') {
      const op = tokens[pos++];
      const r = parseTerm();
      v = op === '+' ? v + r : v - r;
    }
    return v;
  };
  const parseTerm = () => {
    let v = parseFactor();
    while (peek() === '*' || peek() === '/') {
      const op = tokens[pos++];
      const r = parseFactor();
      v = op === '*' ? v * r : v / r;
    }
    return v;
  };
  const parseFactor = () => {
    if (peek() === '(') {
      pos++;
      const v = parseExpr();
      if (tokens[pos++] !== ')') throw new Error('unbalanced');
      return v;
    }
    const n = Number(tokens[pos++]);
    if (Number.isNaN(n)) throw new Error('invalid token');
    return n;
  };
  const result = parseExpr();
  if (pos !== tokens.length) throw new Error('trailing input');
  return result;
}

app.get('/calc', (req, res) => {
  try {
    res.send(String(safeCalc(req.query.expr)));
  } catch (err) {
    res.status(400).send('invalid expression');
  }
});

app.listen(3000);
