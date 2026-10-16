// Safe JS counterpart.
const child_process = require('child_process');
const bcrypt = require('bcrypt');
const axios = require('axios');
const DOMPurify = require('dompurify');

const ALLOWED_HOSTS = ['api.example.com'];

function getUser(connection, userId) {
  return connection.query('SELECT * FROM users WHERE id = ?', [userId]);
}

function runBackup(targetDir) {
  return child_process.execFile('tar', ['-czf', 'backup.tar.gz', targetDir]);
}

function loadConfig(raw) {
  return JSON.parse(raw);
}

function showMessage(el, userInput) {
  el.textContent = userInput;
}

function restoreSession(data) {
  return JSON.parse(data);
}

function proxyRequest(host) {
  if (!ALLOWED_HOSTS.includes(host)) throw new Error('host not allowed');
  return axios.get('https://' + host + '/api/data');
}

async function checkLogin(password, storedHash) {
  return await bcrypt.compare(password, storedHash);
}

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}
