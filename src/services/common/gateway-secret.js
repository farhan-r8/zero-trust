const crypto = require('node:crypto');
const { recordAuditEvent } = require('../../audit/log-event');

function endpointForRequest(req) {
  const path = req.path ?? '';
  const route = path === '/nilai' ? '/nilai'
    : /^\/nilai\/\d+$/.test(path) ? '/nilai/:id'
      : /^\/kelas\/\d+\/finalisasi$/.test(path) ? '/kelas/:id/finalisasi'
        : path === '/transkrip/sinkron' ? '/transkrip/sinkron'
          : /^\/transkrip\/[^/]+$/.test(path) ? '/transkrip/:nim'
            : '/unknown';
  return `${req.method ?? 'UNKNOWN'} ${route}`;
}

function auditGatewaySecretDenial(db, req, sensitiveValues = []) {
  try {
    recordAuditEvent(db, {
      subjectType: 'anonymous',
      endpoint: endpointForRequest(req),
      deviceId: req.get('x-device-id'),
      result: 'deny',
      reason: 'gateway_secret.invalid',
      requestId: crypto.randomUUID(),
      sensitiveValues
    });
  } catch {
    // Denied requests remain denied if the audit store is unavailable.
  }
}

function equalSecret(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const left = Buffer.from(actual, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function gatewaySecretMiddleware(expectedSecret, db, sensitiveValues = []) {
  return (req, res, next) => {
    const actual = req.get('x-gateway-secret');
    if (!expectedSecret || !equalSecret(actual, expectedSecret)) {
      auditGatewaySecretDenial(db, req, [expectedSecret, ...sensitiveValues]);
      return res.status(403).json({ error: 'Akses internal ditolak' });
    }
    return next();
  };
}

module.exports = { equalSecret, gatewaySecretMiddleware };
