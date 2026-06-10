// Intentionally-vulnerable web service for DAST benchmarking (test fixture only).
//
// Each route is annotated with the CWE it is meant to expose so a DAST tool
// (nuclei, ZAP, ...) can be scored against known ground truth. The OpenAPI
// description of every endpoint lives in ./openapi.yml.
//
// Run:  npm install && npm start      (listens on http://localhost:3000)
// DO NOT expose this service on a public network — see README.md ("Exposure").

const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// In-memory demo database.
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
  db.run("INSERT INTO users (username, password) VALUES ('alice', 'password123'), ('bob', 'hunter2')");
});

// Insecure global CORS — reflects any origin (CWE-942: Permissive Cross-domain Policy).
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

app.get('/', (_req, res) =>
  res.send('<h2>guinea-pig dynamic target</h2><p>See /openapi.yml for the endpoint list.</p>'));

// Serve the OpenAPI document so scanners (zap-api-scan) can import it.
app.get('/openapi.yml', (_req, res) =>
  res.type('text/yaml').sendFile(path.join(__dirname, 'openapi.yml')));

// CWE-79: Reflected Cross-Site Scripting — query echoed into HTML unescaped.
//   GET /search?q=<script>alert(1)</script>
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<html><body><h1>Results for: ${q}</h1></body></html>`);
});

// CWE-89: SQL Injection — credentials concatenated into the query.
//   POST /login {"username":"' OR '1'='1","password":"x"}
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(sql, (err, row) => {
    if (err) return res.status(500).send(`SQL error: ${err.message}`); // CWE-209: verbose error
    return row ? res.send(`Logged in as ${row.username}`) : res.status(401).send('Invalid credentials');
  });
});

// CWE-89: SQL Injection (reflected, GET) — id concatenated into the query.
//   GET /users?id=1 OR 1=1
app.get('/users', (req, res) => {
  const id = req.query.id || '0';
  db.all(`SELECT id, username FROM users WHERE id = ${id}`, (err, rows) => {
    if (err) return res.status(500).send(`SQL error: ${err.message}`);
    return res.json(rows);
  });
});

// CWE-78: OS Command Injection — host interpolated into a shell command.
//   GET /ping?host=127.0.0.1;id
app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  try {
    const out = execSync(`ping -c 1 ${host}`).toString();
    res.type('text/plain').send(out);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

// CWE-22: Path Traversal — file read from a user-supplied path with no containment.
//   GET /download?file=../../etc/passwd
app.get('/download', (req, res) => {
  const file = req.query.file || 'readme.txt';
  fs.readFile(path.join(__dirname, 'public', file), (err, data) => {
    if (err) return res.status(404).send(`Not found: ${err.message}`);
    return res.type('application/octet-stream').send(data);
  });
});

// CWE-601: Open Redirect — redirects to any user-supplied URL.
//   GET /redirect?url=https://evil.example
app.get('/redirect', (req, res) => res.redirect(req.query.url || '/'));

// CWE-918: Server-Side Request Forgery — server fetches an arbitrary URL.
//   GET /fetch?url=http://169.254.169.254/latest/meta-data/
app.get('/fetch', (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('missing url');
  http.get(target, (r) => {
    let body = '';
    r.on('data', (c) => (body += c));
    r.on('end', () => res.type('text/plain').send(body));
  }).on('error', (e) => res.status(502).send(e.message));
});

// CWE-1004 / CWE-614: session cookie set without HttpOnly/Secure/SameSite.
//   GET /set-cookie
app.get('/set-cookie', (req, res) => {
  res.setHeader('Set-Cookie', 'session=abc123'); // no HttpOnly, no Secure, no SameSite
  res.send('cookie set');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`dynamic target listening on http://localhost:${PORT}`));
