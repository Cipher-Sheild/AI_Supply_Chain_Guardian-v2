// Deliberately vulnerable JS fixture. One function per rule.
const child_process = require('child_process');
const crypto = require('crypto');
const serialize = require('node-serialize');
const axios = require('axios');

// js-sql-injection-string-concat
function getUser(connection, userId) {
  const query = 'SELECT * FROM users WHERE id = ' + userId;
  return connection.query(query);
}

// js-insecure-tls-verification-disabled
const agentOptions = { rejectUnauthorized: false, keepAlive: true };

// js-command-injection
function runBackup(targetDir) {
  const cmd = 'tar -czf backup.tar.gz ' + targetDir;
  return child_process.exec(cmd);
}

// js-eval-on-input
function loadConfig(raw) {
  return eval(raw);
}

// js-xss-dangerous-html
function showMessage(el, userInput) {
  const html = '<p>' + userInput + '</p>';
  el.innerHTML = html;
}

// js-insecure-deserialization
function restoreSession(data) {
  return serialize.unserialize(data);
}

// js-ssrf-user-controlled-url
function proxyRequest(host) {
  const url = 'https://' + host + '/api/data';
  return axios.get(url);
}

// js-plaintext-password-comparison
function checkLogin(password, stored) {
  return password === stored;
}

// js-weak-password-hashing
function hashPassword() {
  return crypto.createHash('md5');
}
