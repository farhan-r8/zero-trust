const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const { createAccessToken, createServiceToken } = require('../auth/tokens');
const { hashRefreshToken, createRefreshToken, expiresAtFrom } = require('../auth/refresh');
const { recordAuditEvent } = require('../audit/log-event');

const INVALID_CREDENTIALS = { error: 'Kredensial atau perangkat tidak valid' };
const INVALID_TOKEN = { error: 'Token tidak valid atau tidak berlaku' };
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('not-a-real-user-password', 10);

function constantTimeStringEqual(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const actualBytes = Buffer.from(actual, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  if (actualBytes.length !== expectedBytes.length) return false;
  return crypto.timingSafeEqual(actualBytes, expectedBytes);
}

function validText(value, maxLength = 200) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
}

function auditAuthEvent(db, config, req, { subjectId = null, subjectType = 'anonymous', endpoint, result, reason }) {
  recordAuditEvent(db, {
    subjectId,
    subjectType,
    endpoint,
    deviceId: req.get('x-device-id'),
    result,
    reason,
    requestId: req.get('x-request-id'),
    sensitiveValues: [config.jwtSecret, config.gatewaySecret, config.serviceClientSecret]
  });
}

function auditOrUnavailable(res, callback) {
  try {
    callback();
    return true;
  } catch {
    res.status(503).json({ error: 'Audit tidak tersedia' });
    return false;
  }
}

function createAuthRouter({ db, config }) {
  const router = express.Router();

  router.post('/login', (req, res) => {
    const { username, password } = req.body ?? {};
    const deviceId = req.get('x-device-id');
    if (!validText(username) || !validText(password, 1024) || !validText(deviceId)) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        endpoint: 'POST /auth/login', result: 'deny', reason: 'auth.input_invalid'
      }))) return;
      return res.status(400).json({ error: 'Input tidak valid' });
    }

    const user = db.prepare('SELECT id, username, password_hash, role, is_active FROM users WHERE username=?').get(username);
    const passwordMatches = bcrypt.compareSync(password, user?.password_hash ?? DUMMY_PASSWORD_HASH);
    const device = user && user.is_active && passwordMatches
      ? db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=? AND is_active=1').get(user.id, deviceId)
      : null;
    if (!user || !user.is_active || !passwordMatches || !device) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        subjectId: user?.is_active ? user.id : null,
        subjectType: user?.is_active ? 'user' : 'anonymous',
        endpoint: 'POST /auth/login', result: 'deny', reason: 'auth.credentials_or_device_invalid'
      }))) return;
      return res.status(401).json(INVALID_CREDENTIALS);
    }

    const accessToken = createAccessToken(user, config.jwtSecret);
    const refreshToken = createRefreshToken();
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)')
          .run(user.id, hashRefreshToken(refreshToken), expiresAtFrom());
        auditAuthEvent(db, config, req, {
          subjectId: user.id, subjectType: 'user', endpoint: 'POST /auth/login', result: 'allow', reason: 'auth.login.succeeded'
        });
      })();
    } catch {
      return res.status(503).json({ error: 'Autentikasi tidak tersedia' });
    }
    return res.status(200).json({
      token_type: 'Bearer',
      access_token: accessToken,
      expires_in: 600,
      refresh_token: refreshToken,
      refresh_expires_in: 86400
    });
  });

  router.post('/refresh', (req, res) => {
    const { refreshToken } = req.body ?? {};
    const deviceId = req.get('x-device-id');
    if (!validText(refreshToken, 200) || !validText(deviceId)) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        endpoint: 'POST /auth/refresh', result: 'deny', reason: 'auth.input_invalid'
      }))) return;
      return res.status(400).json({ error: 'Input tidak valid' });
    }

    const digest = hashRefreshToken(refreshToken);
    const row = db.prepare(`SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked_at,
      u.role, u.is_active FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id WHERE rt.token_hash=?`).get(digest);
    const device = row && row.is_active
      ? db.prepare('SELECT 1 FROM devices WHERE user_id=? AND device_id=? AND is_active=1').get(row.user_id, deviceId)
      : null;
    const expiresAt = row ? Date.parse(row.expires_at) : Number.NaN;
    if (!row || row.revoked_at || !Number.isFinite(expiresAt) || expiresAt <= Date.now() || !row.is_active || !device) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        subjectId: row?.user_id ?? null,
        subjectType: row?.user_id ? 'user' : 'anonymous',
        endpoint: 'POST /auth/refresh', result: 'deny', reason: 'auth.refresh_invalid_or_revoked'
      }))) return;
      return res.status(401).json(INVALID_TOKEN);
    }

    const nextRefreshToken = createRefreshToken();
    const nextExpiresAt = expiresAtFrom();
    const accessToken = createAccessToken({ id: row.user_id, role: row.role }, config.jwtSecret);
    const rotate = db.transaction(() => {
      const changed = db.prepare(`UPDATE refresh_tokens SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id=? AND revoked_at IS NULL AND expires_at>?`).run(row.id, new Date().toISOString());
      if (changed.changes !== 1) {
        auditAuthEvent(db, config, req, {
          subjectId: row.user_id, subjectType: 'user', endpoint: 'POST /auth/refresh',
          result: 'deny', reason: 'auth.refresh_reuse_or_race'
        });
        return false;
      }
      db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)')
        .run(row.user_id, hashRefreshToken(nextRefreshToken), nextExpiresAt);
      auditAuthEvent(db, config, req, {
        subjectId: row.user_id, subjectType: 'user', endpoint: 'POST /auth/refresh',
        result: 'allow', reason: 'auth.refresh.rotated'
      });
      return true;
    });
    let rotated;
    try {
      rotated = rotate();
    } catch {
      return res.status(503).json({ error: 'Autentikasi tidak tersedia' });
    }
    if (!rotated) return res.status(401).json(INVALID_TOKEN);
    return res.status(200).json({
      token_type: 'Bearer',
      access_token: accessToken,
      expires_in: 600,
      refresh_token: nextRefreshToken,
      refresh_expires_in: 86400
    });
  });

  router.post('/logout', (req, res) => {
    const { refreshToken } = req.body ?? {};
    if (!validText(refreshToken, 200)) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        endpoint: 'POST /auth/logout', result: 'deny', reason: 'auth.input_invalid'
      }))) return;
      return res.status(400).json({ error: 'Input tidak valid' });
    }
    const tokenHash = hashRefreshToken(refreshToken);
    const row = db.prepare('SELECT id, user_id FROM refresh_tokens WHERE token_hash=?').get(tokenHash);
    if (!row) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        endpoint: 'POST /auth/logout', result: 'deny', reason: 'auth.logout_token_unknown'
      }))) return;
      return res.status(401).json(INVALID_TOKEN);
    }
    try {
      db.transaction(() => {
        db.prepare(`UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
          WHERE id=?`).run(row.id);
        auditAuthEvent(db, config, req, {
          subjectId: row.user_id, subjectType: 'user', endpoint: 'POST /auth/logout',
          result: 'allow', reason: 'auth.logout.revoked'
        });
      })();
    } catch {
      return res.status(503).json({ error: 'Autentikasi tidak tersedia' });
    }
    return res.status(204).end();
  });

  router.post('/service', (req, res) => {
    const { clientId, clientSecret } = req.body ?? {};
    if (!validText(clientId) || !validText(clientSecret, 1024)) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        endpoint: 'POST /auth/service', result: 'deny', reason: 'auth.input_invalid'
      }))) return;
      return res.status(400).json({ error: 'Input tidak valid' });
    }
    if (!constantTimeStringEqual(clientId, config.serviceClientId) ||
        !constantTimeStringEqual(clientSecret, config.serviceClientSecret)) {
      if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
        endpoint: 'POST /auth/service', result: 'deny', reason: 'auth.service_credentials_invalid'
      }))) return;
      return res.status(401).json({ error: 'Autentikasi service ditolak' });
    }
    if (!auditOrUnavailable(res, () => auditAuthEvent(db, config, req, {
      subjectType: 'service:grade-service', endpoint: 'POST /auth/service', result: 'allow', reason: 'auth.service_token_issued'
    }))) return;
    const token = createServiceToken(config.jwtSecret);
    return res.status(200).json({ token_type: 'Bearer', access_token: token, expires_in: 300 });
  });

  return router;
}

module.exports = { createAuthRouter };
