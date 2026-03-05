const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const serialize = require('serialize-javascript');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VULN: Hardcoded secret
const JWT_SECRET = "super_secret_key_123";
const ADMIN_PASSWORD = "admin123";

// VULN: MongoDB connection string with credentials
mongoose.connect('mongodb://admin:password123@localhost:27017/myapp');

// VULN: SQL Injection via string concatenation (simulated with raw query)
app.get('/users', (req, res) => {
  const userId = req.query.id;
  // SQL Injection - unsanitized user input in query
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  res.send('Query: ' + query);
});

// VULN: Cross-Site Scripting (XSS) - reflected
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // XSS - directly embedding user input in HTML response
  res.send('<html><body><h1>Search results for: ' + searchTerm + '</h1></body></html>');
});

// VULN: Command Injection
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // Command injection - unsanitized input passed to exec
  exec('ping -c 3 ' + host, (error, stdout, stderr) => {
    res.send(stdout || stderr);
  });
});

// VULN: Path Traversal
const fs = require('fs');
const path = require('path');
app.get('/file', (req, res) => {
  const filename = req.query.name;
  // Path traversal - no sanitization of file path
  const filePath = path.join('/uploads', filename);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});

// VULN: Insecure JWT - no algorithm restriction
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (password === ADMIN_PASSWORD) {
    // Weak JWT with no expiration
    const token = jwt.sign({ user: username, role: 'admin' }, JWT_SECRET);
    res.json({ token });
  }
  res.status(401).send('Unauthorized');
});

// VULN: Server-Side Request Forgery (SSRF)
const fetch = require('node-fetch');
app.get('/proxy', async (req, res) => {
  const url = req.query.url;
  // SSRF - fetching arbitrary URLs from user input
  const response = await fetch(url);
  const body = await response.text();
  res.send(body);
});

// VULN: Insecure deserialization
app.post('/data', (req, res) => {
  const userInput = req.body.data;
  // Dangerous eval of user-controlled data
  const result = eval(userInput);
  res.json({ result });
});

// VULN: Regex DoS (ReDoS)
app.get('/validate-email', (req, res) => {
  const email = req.query.email;
  // ReDoS vulnerable regex
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

// VULN: Information disclosure via error messages
app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    cwd: process.cwd(),
    platform: process.platform,
    nodeVersion: process.version
  });
});

// VULN: Open redirect
app.get('/redirect', (req, res) => {
  const target = req.query.url;
  // Open redirect - no validation of redirect target
  res.redirect(target);
});

// VULN: No rate limiting, no CSRF protection
app.post('/transfer', (req, res) => {
  const { to, amount } = req.body;
  res.json({ status: 'transferred', to, amount });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
