const { verifyToken } = require('../auth/tokens');
const { bearerFromHeader } = require('../auth/middleware');
const { recordAuditEvent } = require('../audit/log-event');

const ACTIONS = Object.freeze({
  GRADES_READ: 'grades.read',
  GRADES_UPDATE: 'grades.update',
  GRADES_FINALIZE: 'grades.finalize',
  TRANSCRIPTS_READ: 'transcripts.read',
  TRANSCRIPTS_SYNC: 'transcripts.sync'
});

function positiveId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return value;
  if (typeof value === 'string' && /^[1-9]\d*$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) return parsed;
  }
  return null;
}

function getLocalMinutes(date, timeZone) {
  if (!(date instanceof Date) || !Number.isFinite(date.getTime())) return null;
  try {
    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone,
      hour: '2-digit',
      minute: '2-digit',
      hourCycle: 'h23'
    }).formatToParts(date);
    const hour = Number(parts.find((part) => part.type === 'hour')?.value);
    const minute = Number(parts.find((part) => part.type === 'minute')?.value);
    if (!Number.isInteger(hour) || !Number.isInteger(minute)) return null;
    return hour * 60 + minute;
  } catch {
    return null;
  }
}

function parseClock(value) {
  if (typeof value !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) return null;
  const [hour, minute] = value.split(':').map(Number);
  return hour * 60 + minute;
}

function isWithinAccessWindow(date, { timeZone = 'Asia/Jakarta', start = '07:00', end = '21:00' } = {}) {
  const localMinutes = getLocalMinutes(date, timeZone);
  const startMinutes = parseClock(start);
  const endMinutes = parseClock(end);
  if (localMinutes === null || startMinutes === null || endMinutes === null || startMinutes >= endMinutes) return false;
  return localMinutes >= startMinutes && localMinutes <= endMinutes;
}

function endpointForAction(action) {
  const endpoints = {
    [ACTIONS.GRADES_READ]: 'GET /nilai',
    [ACTIONS.GRADES_UPDATE]: 'PUT /nilai/:id',
    [ACTIONS.GRADES_FINALIZE]: 'POST /kelas/:id/finalisasi',
    [ACTIONS.TRANSCRIPTS_READ]: 'GET /transkrip/:nim',
    [ACTIONS.TRANSCRIPTS_SYNC]: 'POST /transkrip/sinkron'
  };
  return endpoints[action] ?? 'UNKNOWN /unknown';
}

function auditDecision(db, { claims, userId, deviceId, action, decision, reason, requestId, sensitiveValues }) {
  const subjectType = claims?.typ === 'service'
    ? `service:${claims.sub}`
    : userId ? 'user' : 'anonymous';
  recordAuditEvent(db, {
    subjectId: userId,
    subjectType,
    endpoint: endpointForAction(action),
    deviceId,
    result: decision,
    reason,
    requestId,
    sensitiveValues
  });
}

function evaluateAction(db, { claims, user, userId, resource, action, now, timeZone, accessWindow }) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return { decision: 'deny', reason: 'context.invalid' };

  if (action === ACTIONS.GRADES_READ) {
    if (claims.role === 'mahasiswa') {
      const requestedStudentId = resource.studentId === undefined ? userId : positiveId(resource.studentId);
      if (requestedStudentId === null) return { decision: 'deny', reason: 'context.student_required' };
      if (requestedStudentId !== userId) return { decision: 'deny', reason: 'grades.student_not_owner' };
      if (resource.gradeId !== undefined) {
        const gradeId = positiveId(resource.gradeId);
        const grade = gradeId && db.prepare('SELECT student_id, class_id FROM grades WHERE id=?').get(gradeId);
        if (!grade || grade.student_id !== userId) return { decision: 'deny', reason: 'grades.not_found_or_not_owned' };
        if (resource.classId !== undefined && positiveId(resource.classId) !== grade.class_id) return { decision: 'deny', reason: 'context.class_mismatch' };
      }
      if (resource.classId !== undefined) {
        const classId = positiveId(resource.classId);
        const enrollment = classId && db.prepare('SELECT 1 FROM enrollments WHERE class_id=? AND student_id=?').get(classId, userId);
        if (!enrollment) return { decision: 'deny', reason: 'grades.not_enrolled' };
      }
      return { decision: 'allow', reason: 'grades.student_self' };
    }
    if (claims.role === 'dosen') {
      const gradeId = resource.gradeId === undefined ? null : positiveId(resource.gradeId);
      const classId = resource.classId === undefined ? null : positiveId(resource.classId);
      const grade = gradeId ? db.prepare('SELECT class_id FROM grades WHERE id=?').get(gradeId) : null;
      if (gradeId && !grade) return { decision: 'deny', reason: 'grades.not_found' };
      if (grade && classId && grade.class_id !== classId) return { decision: 'deny', reason: 'context.class_mismatch' };
      const resolvedClassId = grade?.class_id ?? classId;
      if (!resolvedClassId) return { decision: 'deny', reason: 'context.class_required' };
      const owned = db.prepare('SELECT 1 FROM classes WHERE id=? AND lecturer_id=?').get(resolvedClassId, userId);
      if (!owned) return { decision: 'deny', reason: 'grades.class_not_assigned' };
      return { decision: 'allow', reason: 'grades.lecturer_class' };
    }
    return { decision: 'deny', reason: 'role.not_allowed' };
  }

  if (action === ACTIONS.GRADES_UPDATE) {
    if (claims.role !== 'dosen') return { decision: 'deny', reason: 'role.not_allowed' };
    const gradeId = positiveId(resource.gradeId);
    if (!gradeId) return { decision: 'deny', reason: 'context.grade_required' };
    const grade = db.prepare(`SELECT g.id, g.is_final, c.lecturer_id FROM grades g
      JOIN classes c ON c.id=g.class_id WHERE g.id=?`).get(gradeId);
    if (!grade) return { decision: 'deny', reason: 'grades.not_found' };
    if (grade.lecturer_id !== userId) return { decision: 'deny', reason: 'grades.class_not_assigned' };
    if (grade.is_final) return { decision: 'deny', reason: 'grades.already_final' };
    if (!isWithinAccessWindow(now, { ...accessWindow, timeZone })) return { decision: 'deny', reason: 'access.outside_hours' };
    return { decision: 'allow', reason: 'grades.update_allowed' };
  }

  if (action === ACTIONS.GRADES_FINALIZE) {
    if (claims.role !== 'dosen') return { decision: 'deny', reason: 'role.not_allowed' };
    const classId = positiveId(resource.classId);
    if (!classId) return { decision: 'deny', reason: 'context.class_required' };
    const owned = db.prepare('SELECT 1 FROM classes WHERE id=? AND lecturer_id=?').get(classId, userId);
    if (!owned) return { decision: 'deny', reason: 'grades.class_not_assigned' };
    if (!isWithinAccessWindow(now, { ...accessWindow, timeZone })) return { decision: 'deny', reason: 'access.outside_hours' };
    const completion = db.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN score IS NULL THEN 1 ELSE 0 END) AS missing FROM grades WHERE class_id=?').get(classId);
    if (!completion.total) return { decision: 'deny', reason: 'grades.no_values' };
    if (completion.missing) return { decision: 'deny', reason: 'grades.incomplete' };
    return { decision: 'allow', reason: 'grades.finalize_allowed' };
  }

  if (action === ACTIONS.TRANSCRIPTS_READ) {
    const nim = resource.nim;
    if (claims.role === 'mahasiswa') {
      if (typeof nim !== 'string' || nim.length === 0 || nim.length > 32) {
        return { decision: 'deny', reason: 'context.nim_required' };
      }
      if (nim !== user.nim) {
        return { decision: 'deny', reason: 'transcripts.student_not_owner' };
      }
      return { decision: 'allow', reason: 'transcripts.student_self' };
    }
    if (claims.role === 'admin') {
      if (typeof nim !== 'string' || nim.length === 0 || nim.length > 32) return { decision: 'deny', reason: 'context.nim_required' };
      const exists = db.prepare("SELECT 1 FROM users WHERE nim=? AND role='mahasiswa' AND is_active=1").get(nim);
      return exists ? { decision: 'allow', reason: 'transcripts.admin_read' } : { decision: 'deny', reason: 'transcripts.not_found' };
    }
    return { decision: 'deny', reason: 'role.not_allowed' };
  }

  if (action === ACTIONS.TRANSCRIPTS_SYNC) {
    if (claims.typ !== 'service' || claims.role !== 'service' || claims.sub !== 'grade-service') {
      return { decision: 'deny', reason: 'service.identity_required' };
    }
    if (!Array.isArray(claims.scope) || !claims.scope.includes('transcript:sync')) {
      return { decision: 'deny', reason: 'service.scope_required' };
    }
    const gradeId = positiveId(resource.gradeId);
    if (!gradeId) return { decision: 'deny', reason: 'context.grade_required' };
    const grade = db.prepare('SELECT is_final FROM grades WHERE id=?').get(gradeId);
    if (!grade || !grade.is_final) return { decision: 'deny', reason: 'grades.not_final' };
    return { decision: 'allow', reason: 'transcripts.sync_service' };
  }

  return { decision: 'deny', reason: 'policy.default_deny' };
}

function evaluatePolicy({
  db,
  jwtSecret,
  token,
  deviceId,
  action,
  resource = {},
  now = new Date(),
  timeZone = 'Asia/Jakarta',
  accessWindow = { start: '07:00', end: '21:00' },
  requestId,
  sensitiveValues = []
}) {
  let claims = null;
  let user = null;
  let userId = null;
  let decision;
  let reason;

  if (!db || typeof db.prepare !== 'function') {
    return { allowed: false, decision: 'deny', reason: 'policy.database_unavailable' };
  }

  try {
    claims = verifyToken(token, { secret: jwtSecret, clockTimestamp: Math.floor(now.getTime() / 1000) });
  } catch {
    decision = 'deny';
    reason = 'authentication.token_invalid';
  }

  if (!reason && claims.typ === 'user') {
    const parsedId = positiveId(claims.sub);
    user = parsedId ? db.prepare('SELECT id, role, nim, is_active FROM users WHERE id=?').get(parsedId) : null;
    if (user) userId = user.id;
    if (!user || !user.is_active || user.role !== claims.role) {
      decision = 'deny';
      reason = 'authentication.user_invalid';
    } else {
      if (typeof deviceId !== 'string' || deviceId.length === 0 || deviceId.length > 200) {
        decision = 'deny';
        reason = 'device.required';
      } else {
        const registered = db.prepare(`SELECT 1 FROM devices WHERE user_id=? AND device_id=? AND is_active=1`).get(user.id, deviceId);
        if (!registered) {
          decision = 'deny';
          reason = 'device.not_registered';
        } else {
        }
      }
    }
  } else if (!reason && (claims.typ !== 'service' || claims.role !== 'service')) {
    decision = 'deny';
    reason = 'authentication.token_type_invalid';
  }

  if (!reason) {
    const result = evaluateAction(db, { claims, user, userId, resource, action, now, timeZone, accessWindow });
    decision = result.decision;
    reason = result.reason;
  }

  try {
    auditDecision(db, { claims, userId, deviceId, action, decision, reason, requestId, sensitiveValues: [jwtSecret, ...sensitiveValues] });
  } catch {
    return { allowed: false, decision: 'deny', reason: 'audit.write_failed' };
  }

  return { allowed: decision === 'allow', decision, reason, principal: claims ? { sub: claims.sub, role: claims.role, typ: claims.typ } : null };
}

function createPolicyMiddleware({ db, jwtSecret, action, resourceResolver, config, timeZone, accessWindow, nowProvider }) {
  if (typeof action !== 'string' || typeof resourceResolver !== 'function') {
    throw new TypeError('Policy middleware memerlukan action dan resourceResolver');
  }
  return (req, res, next) => {
    let resource;
    try {
      resource = resourceResolver(req);
    } catch {
      resource = null;
    }
    const result = evaluatePolicy({
      db,
      jwtSecret,
      token: bearerFromHeader(req.get('authorization')),
      deviceId: req.get('x-device-id'),
      action,
      resource,
      now: (nowProvider ?? config?.nowProvider ?? (() => new Date()))(),
      timeZone: timeZone ?? config?.timeZone ?? 'Asia/Jakarta',
      accessWindow: accessWindow ?? {
        start: config?.accessWindowStart ?? '07:00',
        end: config?.accessWindowEnd ?? '21:00'
      },
      requestId: req.get('x-request-id'),
      sensitiveValues: [config?.gatewaySecret, config?.serviceClientSecret]
    });
    if (!result.allowed) {
      const status = result.reason.startsWith('authentication.') || result.reason.startsWith('device.') ? 401 : 403;
      return res.status(status).json({ error: 'Akses ditolak' });
    }
    req.auth = result.principal;
    req.policy = { action, decision: result.decision };
    return next();
  };
}

module.exports = { ACTIONS, evaluatePolicy, createPolicyMiddleware, isWithinAccessWindow };
