// Remediation for CWE-89: SQL Injection
// Fix: Use a parameterized query with a placeholder so untrusted input is treated as data, not SQL.

const express = require('express');
const mysql = require('mysql');

const app = express();
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'app',
});

app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  connection.query(query, [userId], (err, results) => {
    if (err) return res.status(500).send('error');
    res.json(results);
  });
});

app.listen(3000);
