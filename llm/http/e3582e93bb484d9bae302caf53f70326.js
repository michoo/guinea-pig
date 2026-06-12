const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
  db.run("INSERT INTO users (username, password) VALUES ('alice', 'password123'), ('bob', 'hunter2')");
});

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

app.get('/', (_req, res) =>
  res.send('<h2>dynamic target</h2><p>See /openapi.yml for the endpoint list.</p>'));

app.get('/openapi.yml', (_req, res) =>
  res.type('text/yaml').sendFile(path.join(__dirname, 'openapi.yml')));

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<html><body><h1>Results for: ${q}</h1></body></html>`);
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(sql, (err, row) => {
    if (err) return res.status(500).send(`SQL error: ${err.message}`);
    return row ? res.send(`Logged in as ${row.username}`) : res.status(401).send('Invalid credentials');
  });
});

app.get('/users', (req, res) => {
  const id = req.query.id || '0';
  db.all(`SELECT id, username FROM users WHERE id = ${id}`, (err, rows) => {
    if (err) return res.status(500).send(`SQL error: ${err.message}`);
    return res.json(rows);
  });
});

app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  try {
    const out = execSync(`ping -c 1 ${host}`).toString();
    res.type('text/plain').send(out);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.get('/download', (req, res) => {
  const file = req.query.file || 'readme.txt';
  fs.readFile(path.join(__dirname, 'public', file), (err, data) => {
    if (err) return res.status(404).send(`Not found: ${err.message}`);
    return res.type('application/octet-stream').send(data);
  });
});

app.get('/redirect', (req, res) => res.redirect(req.query.url || '/'));

app.get('/fetch', (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('missing url');
  http.get(target, (r) => {
    let body = '';
    r.on('data', (c) => (body += c));
    r.on('end', () => res.type('text/plain').send(body));
  }).on('error', (e) => res.status(502).send(e.message));
});

app.get('/set-cookie', (req, res) => {
  res.setHeader('Set-Cookie', 'session=abc123');
  res.send('cookie set');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`dynamic target listening on http://localhost:${PORT}`));
