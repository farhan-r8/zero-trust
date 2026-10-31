const crypto = require('node:crypto');

function isSafeDeviceId(value, sensitiveValues = []) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 200) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  if (sensitiveValues.some((secret) => typeof secret === 'string' && secret.length > 0 && value === secret)) return null;
  const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
  if (value.length >= 32 && !canonicalUuid) return null;
  return value;
}

function recordAuditEvent(db, {
  subjectId = null,
  subjectType = 'anonymous',
  endpoint,
  deviceId = null,
  result,
  reason,
  requestId,
  sensitiveValues = []
}) {
  if (!db || typeof db.prepare !== 'function') throw new Error('Audit database unavailable');
  const safeSubjectId = Number.isSafeInteger(subjectId) && subjectId > 0 ? subjectId : null;
  const safeSubjectType = ['user', 'anonymous', 'service:grade-service'].includes(subjectType) ? subjectType : 'anonymous';
  const safeEndpoint = typeof endpoint === 'string' && /^[A-Z]{3,8} \/[A-Za-z0-9_:/-]{1,180}$/.test(endpoint)
    ? endpoint
    : 'UNKNOWN /unknown';
  const safeResult = ['allow', 'deny', 'error'].includes(result) ? result : 'error';
  const safeReason = typeof reason === 'string' && /^[a-z0-9._-]{1,100}$/.test(reason) ? reason : 'audit.invalid_reason';
  const safeRequestId = typeof requestId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestId) &&
    !sensitiveValues.some((secret) => typeof secret === 'string' && secret.length > 0 && requestId === secret)
    ? requestId
    : crypto.randomUUID();

  db.prepare(`INSERT INTO audit_logs
    (subject_id, subject_type, endpoint, device_id, result, reason, request_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(safeSubjectId, safeSubjectType, safeEndpoint, isSafeDeviceId(deviceId, sensitiveValues), safeResult, safeReason, safeRequestId);
}

module.exports = { recordAuditEvent, isSafeDeviceId };
