const crypto = require('node:crypto');

const REFRESH_TTL_MS = 24 * 60 * 60 * 1000;

function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

function createRefreshToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function expiresAtFrom(now = Date.now()) {
  return new Date(now + REFRESH_TTL_MS).toISOString();
}

module.exports = { REFRESH_TTL_MS, hashRefreshToken, createRefreshToken, expiresAtFrom };
