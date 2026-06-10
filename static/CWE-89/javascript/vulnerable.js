// CWE-89: SQL Injection
// Untrusted request input is concatenated directly into a SQL query string.
// Vulnerable sink: connection.query(`... ${req.params.id}`)

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
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  connection.query(query, (err, results) => {
    if (err) return res.status(500).send('error');
    res.json(results);
  });
});

app.listen(3000);
