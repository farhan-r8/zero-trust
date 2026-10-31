const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { initializeDatabase } = require('../src/db/init');
const { openDatabase } = require('../src/db/connection');
const { createGatewayApp } = require('../src/gateway/app');
const { createGradeServiceApp } = require('../src/services/grade/app');
const { createTranscriptServiceApp } = require('../src/services/transcript/app');
const { processSyncJobs } = require('../src/services/grade/sync-jobs');
const { createServiceToken } = require('../src/auth/tokens');

const JWT_SECRET = 'integration-test-secret-with-more-than-thirty-two-bytes';
const GATEWAY_SECRET = 'integration-gateway-secret-with-more-than-thirty-two-bytes';
const SERVICE_CLIENT_ID = 'grade-service-integration';
const SERVICE_CLIENT_SECRET = 'integration-service-secret-never-log-this';

function jakartaTime(hour, minute = 0) {
  return new Date(Date.UTC(2026, 0, 15, hour - 7, minute));
}

async function listen(app) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
    server.once('error', reject);
  });
}

async function setup(t, { failSync = false, upstreamFailure = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zero-trust-integration-'));
  const dbPath = path.join(dir, 'integration.sqlite');
  initializeDatabase(dbPath);
  const db = openDatabase(dbPath);
  const clock = { current: jakartaTime(12) };
  const config = {
    jwtSecret: JWT_SECRET,
    gatewaySecret: GATEWAY_SECRET,
    serviceClientId: SERVICE_CLIENT_ID,
    serviceClientSecret: SERVICE_CLIENT_SECRET,
    timeZone: 'Asia/Jakarta',
    accessWindowStart: '07:00',
    accessWindowEnd: '21:00',
    upstreamTimeoutMs: 1000,
    nowProvider: () => clock.current,
    gatewayBaseUrl: failSync ? 'http://127.0.0.1:1' : undefined
  };
  const gradeServer = await listen(createGradeServiceApp({ db, config }));
  const transcriptServer = await listen(createTranscriptServiceApp({ db, config }));
  let slowServer = null;
  if (upstreamFailure === 'timeout') {
    slowServer = http.createServer(() => {});
    await listen(slowServer);
    config.upstreamTimeoutMs = 50;
  }
  const gatewayConfig = {
    ...config,
    gradeServiceUrl: upstreamFailure === 'timeout'
      ? `http://127.0.0.1:${slowServer.address().port}`
      : upstreamFailure === 'unavailable' ? 'http://127.0.0.1:1' : `http://127.0.0.1:${gradeServer.address().port}`,
    transcriptServiceUrl: `http://127.0.0.1:${transcriptServer.address().port}`
  };
  const gatewayServer = await listen(createGatewayApp({ db, config: gatewayConfig }));
  if (!failSync) config.gatewayBaseUrl = `http://127.0.0.1:${gatewayServer.address().port}`;

  t.after(async () => {
    for (const server of [gatewayServer, gradeServer, transcriptServer, ...(slowServer ? [slowServer] : [])]) {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const byUsername = (username) => db.prepare('SELECT id FROM users WHERE username=?').get(username).id;
  const classId = (code) => db.prepare('SELECT id FROM classes WHERE class_code=?').get(code).id;
  const gradeId = (student, code) => db.prepare('SELECT id FROM grades WHERE student_id=? AND class_id=?').get(byUsername(student), classId(code)).id;
  const deviceId = (username) => db.prepare('SELECT device_id FROM devices WHERE user_id=?').get(byUsername(username)).device_id;
  return {
    db,
    gatewayUrl: `http://127.0.0.1:${gatewayServer.address().port}`,
    gradeUrl: `http://127.0.0.1:${gradeServer.address().port}`,
    transcriptUrl: `http://127.0.0.1:${transcriptServer.address().port}`,
    config,
    clock,
    ids: { byUsername, classId, gradeId, deviceId }
  };
}

async function request(url, method, { token, deviceId, gatewaySecret, body } = {}) {
  const headers = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  if (deviceId) headers['x-device-id'] = deviceId;
  if (gatewaySecret) headers['x-gateway-secret'] = gatewaySecret;
  const response = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = response.status === 204 ? null : await response.json();
  return { response, data };
}

async function login(gatewayUrl, username, password, deviceId) {
  return request(`${gatewayUrl}/auth/login`, 'POST', { deviceId, body: { username, password } });
}

test('Gateway menegakkan policy, proxy layanan, dan finalisasi menyinkronkan transkrip secara idempoten', async (t) => {
  const { db, gatewayUrl, gradeUrl, transcriptUrl, config, clock, ids } = await setup(t);
  const student = await login(gatewayUrl, 'mhs1', 'MhsSatu!2026', ids.deviceId('mhs1'));
  const studentToken = student.data.access_token;
  const ownGrades = await request(`${gatewayUrl}/nilai`, 'GET', { token: studentToken, deviceId: ids.deviceId('mhs1') });
  assert.equal(ownGrades.response.status, 200);
  assert.ok(ownGrades.data.data.length > 0);
  assert.ok(ownGrades.data.data.every((row) => row.studentName === 'Mahasiswa Satu'));

  const otherStudentGrades = await request(`${gatewayUrl}/nilai?studentId=${ids.byUsername('mhs2')}`, 'GET', { token: studentToken, deviceId: ids.deviceId('mhs1') });
  assert.equal(otherStudentGrades.response.status, 403);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE endpoint='GET /nilai' AND result='deny' AND reason='grades.student_not_owner'").get().n, 1);

  const lecturer = await login(gatewayUrl, 'dosen1', 'DosenSatu!2026', ids.deviceId('dosen1'));
  const classGrades = await request(`${gatewayUrl}/nilai?classId=${ids.classId('KI-501')}`, 'GET', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1') });
  assert.equal(classGrades.response.status, 200);
  const otherClass = await request(`${gatewayUrl}/nilai?classId=${ids.classId('KI-502')}`, 'GET', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1') });
  assert.equal(otherClass.response.status, 403);

  const admin = await login(gatewayUrl, 'admin', 'AdminDemo!2026', ids.deviceId('admin'));
  const gradeId = ids.gradeId('mhs1', 'KI-501');
  const adminTranscript = await request(`${gatewayUrl}/transkrip/230001`, 'GET', { token: admin.data.access_token, deviceId: ids.deviceId('admin') });
  assert.equal(adminTranscript.response.status, 200);
  const adminEdit = await request(`${gatewayUrl}/nilai/${gradeId}`, 'PUT', { token: admin.data.access_token, deviceId: ids.deviceId('admin'), body: { score: 77 } });
  assert.equal(adminEdit.response.status, 403);

  const updateFirst = await request(`${gatewayUrl}/nilai/${gradeId}`, 'PUT', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1'), body: { score: 88 } });
  assert.equal(updateFirst.response.status, 200);
  const remaining = db.prepare('SELECT id FROM grades WHERE class_id=? AND score IS NULL').all(ids.classId('KI-501'));
  for (const grade of remaining) {
    const update = await request(`${gatewayUrl}/nilai/${grade.id}`, 'PUT', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1'), body: { score: 75 } });
    assert.equal(update.response.status, 200);
  }

  clock.current = jakartaTime(21, 1);
  const outsideHours = await request(`${gatewayUrl}/nilai/${ids.gradeId('mhs2', 'KI-501')}`, 'PUT', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1'), body: { score: 76 } });
  assert.equal(outsideHours.response.status, 403);
  clock.current = jakartaTime(12);

  const finalized = await request(`${gatewayUrl}/kelas/${ids.classId('KI-501')}/finalisasi`, 'POST', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1'), body: {} });
  assert.equal(finalized.response.status, 200);
  assert.equal(finalized.data.finalized, true);
  assert.equal(finalized.data.sync.status, 'succeeded');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM transcripts t JOIN grades g ON g.id=t.grade_id WHERE g.class_id=?").get(ids.classId('KI-501')).n, 3);

  const editFinal = await request(`${gatewayUrl}/nilai/${gradeId}`, 'PUT', { token: lecturer.data.access_token, deviceId: ids.deviceId('dosen1'), body: { score: 90 } });
  assert.equal(editFinal.response.status, 403);

  const mhsTranscript = await request(`${gatewayUrl}/transkrip/230001`, 'GET', { token: studentToken, deviceId: ids.deviceId('mhs1') });
  assert.equal(mhsTranscript.response.status, 200);
  assert.equal(mhsTranscript.data.data.length, 1);
  const otherNim = await request(`${gatewayUrl}/transkrip/230002`, 'GET', { token: studentToken, deviceId: ids.deviceId('mhs1') });
  assert.equal(otherNim.response.status, 403);

  const issuedService = await request(`${gatewayUrl}/auth/service`, 'POST', { body: { clientId: SERVICE_CLIENT_ID, clientSecret: SERVICE_CLIENT_SECRET } });
  assert.equal(issuedService.response.status, 200);
  const serviceToken = issuedService.data.access_token;
  const finalGradeId = gradeId;
  const repeatSync = await request(`${gatewayUrl}/transkrip/sinkron`, 'POST', { token: serviceToken, body: { gradeId: finalGradeId } });
  assert.equal(repeatSync.response.status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM transcripts WHERE grade_id=?').get(finalGradeId).n, 1);

  const wrongScope = await request(`${gatewayUrl}/transkrip/sinkron`, 'POST', { token: require('jsonwebtoken').sign({
    sub: 'grade-service', role: 'service', typ: 'service', scope: ['transcript:read']
  }, JWT_SECRET, { algorithm: 'HS256', issuer: 'zero-trust-security', audience: 'zero-trust-api', expiresIn: 300 }), body: { gradeId: finalGradeId } });
  assert.equal(wrongScope.response.status, 403);
  const userSync = await request(`${gatewayUrl}/transkrip/sinkron`, 'POST', { token: studentToken, deviceId: ids.deviceId('mhs1'), body: { gradeId: finalGradeId } });
  assert.equal(userSync.response.status, 403);

  const missingGatewaySecret = await request(`${transcriptUrl}/transkrip/sinkron`, 'POST', {
    token: serviceToken, deviceId: 'audit-device-001', body: { gradeId: finalGradeId }
  });
  assert.equal(missingGatewaySecret.response.status, 403);
  const secretDenialAudit = db.prepare(`SELECT endpoint, device_id, result, reason FROM audit_logs
    WHERE endpoint='POST /transkrip/sinkron' AND reason='gateway_secret.invalid' ORDER BY id DESC LIMIT 1`).get();
  assert.deepEqual(secretDenialAudit, {
    endpoint: 'POST /transkrip/sinkron', device_id: 'audit-device-001', result: 'deny', reason: 'gateway_secret.invalid'
  });
  const secretOnly = await request(`${transcriptUrl}/transkrip/sinkron`, 'POST', { gatewaySecret: GATEWAY_SECRET, body: { gradeId: finalGradeId } });
  assert.equal(secretOnly.response.status, 401);
  const userTokenAtTranscript = await request(`${transcriptUrl}/transkrip/sinkron`, 'POST', {
    gatewaySecret: GATEWAY_SECRET, token: studentToken, deviceId: ids.deviceId('mhs1'), body: { gradeId: finalGradeId }
  });
  assert.equal(userTokenAtTranscript.response.status, 403);
  const invalidJwtWithSecret = await request(`${transcriptUrl}/transkrip/sinkron`, 'POST', { gatewaySecret: GATEWAY_SECRET, token: 'invalid.jwt.value', body: { gradeId: finalGradeId } });
  assert.equal(invalidJwtWithSecret.response.status, 401);
  const wrongScopeDirect = await request(`${transcriptUrl}/transkrip/sinkron`, 'POST', {
    gatewaySecret: GATEWAY_SECRET,
    token: require('jsonwebtoken').sign({ sub: 'grade-service', role: 'service', typ: 'service', scope: [] }, JWT_SECRET,
      { algorithm: 'HS256', issuer: 'zero-trust-security', audience: 'zero-trust-api', expiresIn: 300 }),
    body: { gradeId: finalGradeId }
  });
  assert.equal(wrongScopeDirect.response.status, 403);

  const serviceAudit = db.prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE endpoint='POST /transkrip/sinkron' AND result='allow'").get().n;
  assert.ok(serviceAudit >= 4);
  // Touch both service URLs in this test so setup makes it explicit that these are separate listeners.
  assert.ok(gradeUrl.startsWith('http://127.0.0.1:'));
});

test('sinkronisasi gagal tetap konsisten dan retry outbox akhirnya mengisi transkrip', async (t) => {
  const { db, gatewayUrl, config, ids } = await setup(t, { failSync: true });
  const lecturer = await login(gatewayUrl, 'dosen1', 'DosenSatu!2026', ids.deviceId('dosen1'));
  const classId = ids.classId('KI-501');
  db.prepare('UPDATE grades SET score=80 WHERE class_id=?').run(classId);
  const response = await request(`${gatewayUrl}/kelas/${classId}/finalisasi`, 'POST', {
    token: lecturer.data.access_token,
    deviceId: ids.deviceId('dosen1'),
    body: {}
  });
  assert.equal(response.response.status, 202);
  assert.equal(response.data.finalized, true);
  assert.equal(response.data.sync.status, 'pending');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM grades WHERE class_id=? AND is_final=1').get(classId).n, 3);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sync_jobs WHERE status='pending' AND sanitized_error='gateway_unavailable'").get().n, 3);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM transcripts').get().n, 0);
  assert.ok(Date.parse(db.prepare('SELECT MIN(next_attempt_at) AS at FROM sync_jobs').get().at) > Date.now());

  config.gatewayBaseUrl = gatewayUrl;
  db.prepare('UPDATE sync_jobs SET next_attempt_at=NULL WHERE status=\'pending\'').run();
  const retried = await processSyncJobs({ db, config });
  assert.equal(retried.length, 3);
  assert.ok(retried.every((result) => result.status === 'succeeded'));
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sync_jobs WHERE status='succeeded'").get().n, 3);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM transcripts').get().n, 3);
});

test('Gateway menerjemahkan upstream tidak tersedia dan timeout menjadi respons aman', async (t) => {
  const unavailable = await setup(t, { upstreamFailure: 'unavailable' });
  const student = await login(unavailable.gatewayUrl, 'mhs1', 'MhsSatu!2026', unavailable.ids.deviceId('mhs1'));
  const down = await request(`${unavailable.gatewayUrl}/nilai`, 'GET', { token: student.data.access_token, deviceId: unavailable.ids.deviceId('mhs1') });
  assert.equal(down.response.status, 503);
  assert.deepEqual(down.data, { error: 'Layanan upstream tidak tersedia' });

  const timeout = await setup(t, { upstreamFailure: 'timeout' });
  const timeoutStudent = await login(timeout.gatewayUrl, 'mhs1', 'MhsSatu!2026', timeout.ids.deviceId('mhs1'));
  const timedOut = await request(`${timeout.gatewayUrl}/nilai`, 'GET', { token: timeoutStudent.data.access_token, deviceId: timeout.ids.deviceId('mhs1') });
  assert.equal(timedOut.response.status, 504);
  assert.deepEqual(timedOut.data, { error: 'Layanan upstream timeout' });
});
