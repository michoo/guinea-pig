const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// DB in-memory (simple)
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT INTO users (username, password) VALUES ('alice', 'password123')");
});

// 1) Reflected XSS (vuln) - no escaping
// Example: http://localhost:3000/search?q=<script>alert(1)</script>
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // vuln: reflection without escaping
  res.send(`<html><body><h1>Search results for: ${q}</h1></body></html>`);
});

// 2) Login endpoint (vuln SQLi) - vulnerable string concat
// POST /login { "username":"...", "password":"..." }
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  // vuln: query built by concatenation -> SQLi
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(sql, (err, row) => {
    if (err) return res.status(500).send('error');
    if (row) {
      res.send(`Logged in as ${row.username}`);
    } else {
      res.status(401).send('Invalid credentials');
    }
  });
});

app.get('/', (req, res) => res.send('<h2>App vuln-npm — /search and /login</h2>'));

const PORT = 3000;
app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));
