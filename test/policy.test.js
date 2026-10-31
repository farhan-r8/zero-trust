const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const { initializeDatabase } = require('../src/db/init');
const { openDatabase } = require('../src/db/connection');
const { createAccessToken, createServiceToken, ISSUER, AUDIENCE } = require('../src/auth/tokens');
const { ACTIONS, evaluatePolicy, isWithinAccessWindow } = require('../src/policy/engine');

const JWT_SECRET = 'policy-test-secret-with-at-least-thirty-two-bytes';

function atJakarta(hour, minute = 0, second = 0) {
  // 2026-01-15 in Jakarta is UTC+07:00.
  return new Date(Date.UTC(2026, 0, 15, hour - 7, minute, second));
}

function signedServiceToken(scope = ['transcript:sync']) {
  return jwt.sign({ sub: 'grade-service', role: 'service', typ: 'service', scope }, JWT_SECRET, {
    algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, expiresIn: 300
  });
}

async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zero-trust-policy-'));
  const dbPath = path.join(dir, 'policy.sqlite');
  initializeDatabase(dbPath);
  const db = openDatabase(dbPath);
  const id = (username) => db.prepare('SELECT id FROM users WHERE username=?').get(username).id;
  const classId = (code) => db.prepare('SELECT id FROM classes WHERE class_code=?').get(code).id;
  const gradeId = (username, code) => db.prepare('SELECT id FROM grades WHERE student_id=? AND class_id=?').get(id(username), classId(code)).id;
  const ids = { admin: id('admin'), lecturer1: id('dosen1'), lecturer2: id('dosen2'), student1: id('mhs1'), student2: id('mhs2'), class1: classId('KI-501'), class2: classId('KI-502') };
  const device = (username) => db.prepare('SELECT device_id FROM devices WHERE user_id=? AND is_active=1').get(id(username)).device_id;
  t.after(() => {
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { db, ids, device, gradeId };
}

function decide(db, { username, role, id, deviceId, token, ...params }) {
  const userToken = token ?? createAccessToken({ id, role }, JWT_SECRET);
  return evaluatePolicy({
    db, jwtSecret: JWT_SECRET, token: userToken, deviceId,
    now: atJakarta(12), timeZone: 'Asia/Jakarta',
    accessWindow: { start: '07:00', end: '21:00' },
    requestId: `test-${Math.random().toString(36).slice(2)}`,
    ...params
  });
}

test('mahasiswa hanya dapat membaca nilainya sendiri', async (t) => {
  const { db, ids, device, gradeId } = await fixture(t);
  const own = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), action: ACTIONS.GRADES_READ, resource: { gradeId: gradeId('mhs1', 'KI-501') } });
  const other = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), action: ACTIONS.GRADES_READ, resource: { studentId: ids.student2 } });
  assert.equal(own.decision, 'allow');
  assert.equal(other.decision, 'deny');
  assert.equal(other.reason, 'grades.student_not_owner');
});

test('dosen hanya dapat membaca kelas yang diampu', async (t) => {
  const { db, ids, device, gradeId } = await fixture(t);
  const own = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_READ, resource: { classId: ids.class1 } });
  const other = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_READ, resource: { classId: ids.class2 } });
  const mismatchedContext = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_READ, resource: { gradeId: gradeId('mhs1', 'KI-501'), classId: ids.class2 } });
  assert.equal(own.decision, 'allow');
  assert.equal(other.decision, 'deny');
  assert.equal(other.reason, 'grades.class_not_assigned');
  assert.equal(mismatchedContext.reason, 'context.class_mismatch');
});

test('dosen boleh mengubah nilai belum final dan ditolak setelah finalisasi', async (t) => {
  const { db, ids, device, gradeId } = await fixture(t);
  const target = gradeId('mhs1', 'KI-501');
  const before = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_UPDATE, resource: { gradeId: target } });
  db.prepare("UPDATE grades SET is_final=1, finalized_at='2026-01-15T03:00:00.000Z' WHERE id=?").run(target);
  const after = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_UPDATE, resource: { gradeId: target } });
  assert.equal(before.decision, 'allow');
  assert.equal(after.decision, 'deny');
  assert.equal(after.reason, 'grades.already_final');
});

test('update dan finalisasi mengikuti rentang jam Jakarta dengan batas 07:00 dan 21:00 inklusif', async (t) => {
  const { db, ids, device, gradeId } = await fixture(t);
  db.prepare('UPDATE grades SET score=75 WHERE class_id=? AND score IS NULL').run(ids.class1);
  const id = gradeId('mhs1', 'KI-501');
  const update = (time) => decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_UPDATE, resource: { gradeId: id }, now: time });
  const finalize = (time) => decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_FINALIZE, resource: { classId: ids.class1 }, now: time });
  assert.equal(update(atJakarta(7)).decision, 'allow');
  assert.equal(update(atJakarta(20, 59)).decision, 'allow');
  assert.equal(update(atJakarta(21)).decision, 'allow');
  assert.equal(update(atJakarta(21, 1)).decision, 'deny');
  assert.equal(update(atJakarta(6, 59)).decision, 'deny');
  assert.equal(finalize(atJakarta(7)).decision, 'allow');
  assert.equal(finalize(atJakarta(21)).decision, 'allow');
  assert.equal(finalize(atJakarta(21, 1)).decision, 'deny');
  assert.equal(isWithinAccessWindow(new Date('invalid'), { timeZone: 'Asia/Jakarta' }), false);
});

test('admin boleh membaca transkrip mahasiswa yang terdaftar', async (t) => {
  const { db, ids, device } = await fixture(t);
  const allowed = decide(db, { id: ids.admin, role: 'admin', deviceId: device('admin'), action: ACTIONS.TRANSCRIPTS_READ, resource: { nim: '230001' } });
  const missing = decide(db, { id: ids.admin, role: 'admin', deviceId: device('admin'), action: ACTIONS.TRANSCRIPTS_READ, resource: { nim: '999999' } });
  assert.equal(allowed.decision, 'allow');
  assert.equal(missing.decision, 'deny');
});

test('mahasiswa hanya boleh membaca transkrip dengan NIM miliknya', async (t) => {
  const { db, ids, device } = await fixture(t);
  const own = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), action: ACTIONS.TRANSCRIPTS_READ, resource: { nim: '230001' } });
  const other = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), action: ACTIONS.TRANSCRIPTS_READ, resource: { nim: '230002' } });
  const missing = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), action: ACTIONS.TRANSCRIPTS_READ, resource: {} });
  assert.equal(own.decision, 'allow');
  assert.equal(other.decision, 'deny');
  assert.equal(other.reason, 'transcripts.student_not_owner');
  assert.equal(missing.reason, 'context.nim_required');
});

test('finalisasi hanya boleh dilakukan dosen pengampu kelas', async (t) => {
  const { db, ids, device } = await fixture(t);
  db.prepare('UPDATE grades SET score=75 WHERE class_id=? AND score IS NULL').run(ids.class1);
  const own = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_FINALIZE, resource: { classId: ids.class1 } });
  const other = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_FINALIZE, resource: { classId: ids.class2 } });
  const admin = decide(db, { id: ids.admin, role: 'admin', deviceId: device('admin'), action: ACTIONS.GRADES_FINALIZE, resource: { classId: ids.class1 } });
  assert.equal(own.decision, 'allow');
  assert.equal(other.reason, 'grades.class_not_assigned');
  assert.equal(admin.reason, 'role.not_allowed');
});

test('token user ditolak untuk sinkronisasi; service perlu role dan scope tepat', async (t) => {
  const { db, ids, device, gradeId } = await fixture(t);
  const target = gradeId('mhs1', 'KI-501');
  db.prepare("UPDATE grades SET is_final=1, finalized_at='2026-01-15T03:00:00.000Z' WHERE id=?").run(target);
  const resource = { gradeId: target };
  const user = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.TRANSCRIPTS_SYNC, resource });
  const good = evaluatePolicy({ db, jwtSecret: JWT_SECRET, token: createServiceToken(JWT_SECRET), action: ACTIONS.TRANSCRIPTS_SYNC, resource, now: atJakarta(12) });
  const wrongScope = evaluatePolicy({ db, jwtSecret: JWT_SECRET, token: signedServiceToken(['transcript:read']), action: ACTIONS.TRANSCRIPTS_SYNC, resource, now: atJakarta(12) });
  assert.equal(user.decision, 'deny');
  assert.equal(good.decision, 'allow');
  assert.equal(wrongScope.decision, 'deny');
  assert.equal(wrongScope.reason, 'service.scope_required');
});

test('default deny menolak token invalid, device hilang, role, konteks, dan aksi tak dikenal', async (t) => {
  const { db, ids, device } = await fixture(t);
  const missingToken = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), token: 'not-a-jwt', action: ACTIONS.GRADES_READ, resource: {} });
  const missingDevice = decide(db, { id: ids.student1, role: 'mahasiswa', action: ACTIONS.GRADES_READ, resource: {} });
  const unsupportedRole = jwt.sign({ sub: String(ids.student1), role: 'root', typ: 'user' }, JWT_SECRET, { algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, expiresIn: 60 });
  const badRole = decide(db, { token: unsupportedRole, deviceId: device('mhs1'), action: ACTIONS.GRADES_READ, resource: {} });
  const unknownAction = decide(db, { id: ids.student1, role: 'mahasiswa', deviceId: device('mhs1'), action: 'system.admin', resource: {} });
  const missingContext = decide(db, { id: ids.lecturer1, role: 'dosen', deviceId: device('dosen1'), action: ACTIONS.GRADES_READ, resource: {} });
  assert.equal(missingToken.decision, 'deny');
  assert.equal(missingDevice.reason, 'device.required');
  assert.equal(badRole.decision, 'deny');
  assert.equal(unknownAction.reason, 'policy.default_deny');
  assert.equal(missingContext.reason, 'context.class_required');
});

test('setiap keputusan menulis audit aman tanpa token atau secret', async (t) => {
  const { db, ids, device, gradeId } = await fixture(t);
  const secretMarker = 'never-store-this-as-secret-marker';
  const token = createAccessToken({ id: ids.student1, role: 'mahasiswa' }, JWT_SECRET);
  const result = evaluatePolicy({ db, jwtSecret: JWT_SECRET, token, deviceId: device('mhs1'), action: ACTIONS.GRADES_READ, resource: { gradeId: gradeId('mhs1', 'KI-501') }, requestId: 'safe-test-id' });
  const audit = db.prepare('SELECT occurred_at, subject_id, subject_type, endpoint, device_id, result, reason, request_id FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  assert.equal(result.decision, 'allow');
  assert.equal(audit.subject_id, ids.student1);
  assert.equal(audit.subject_type, 'user');
  assert.equal(audit.endpoint, 'GET /nilai');
  assert.equal(audit.device_id, device('mhs1'));
  assert.equal(audit.result, 'allow');
  assert.match(audit.request_id, /^[0-9a-f-]{36}$/i);
  assert.ok(Number.isFinite(Date.parse(audit.occurred_at)));
  assert.equal(JSON.stringify(audit).includes(token), false);
  assert.equal(JSON.stringify(audit).includes(secretMarker), false);
  assert.equal(JSON.stringify(audit).includes(JWT_SECRET), false);
});

test('audit mencatat endpoint dan device pada penolakan device tidak terdaftar', async (t) => {
  const { db, ids } = await fixture(t);
  const result = decide(db, {
    id: ids.student1,
    role: 'mahasiswa',
    deviceId: 'unregistered-device',
    action: ACTIONS.GRADES_READ,
    resource: {}
  });
  const audit = db.prepare('SELECT endpoint, device_id, result, reason FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  assert.equal(result.decision, 'deny');
  assert.equal(audit.endpoint, 'GET /nilai');
  assert.equal(audit.device_id, 'unregistered-device');
  assert.equal(audit.result, 'deny');
  assert.equal(audit.reason, 'device.not_registered');
});
