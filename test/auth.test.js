const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const express = require('express');
const { openDatabase } = require('../src/db/connection');
const { initializeDatabase } = require('../src/db/init');
const { createGatewayApp } = require('../src/gateway/app');
const { verifyToken, ISSUER, AUDIENCE } = require('../src/auth/tokens');
const { hashRefreshToken } = require('../src/auth/refresh');

const JWT_SECRET = 'test-only-jwt-secret-at-least-32-bytes-long';
const OTHER_SECRET = 'other-test-jwt-secret-at-least-32-bytes-long';
const SERVICE_CLIENT_ID = 'grade-service-test';
const SERVICE_CLIENT_SECRET = 'service-test-secret-not-for-production';

async function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zero-trust-auth-'));
  const dbPath = path.join(dir, 'auth.sqlite');
  initializeDatabase(dbPath);
  const db = openDatabase(dbPath);
  const config = { jwtSecret: JWT_SECRET, serviceClientId: SERVICE_CLIENT_ID, serviceClientSecret: SERVICE_CLIENT_SECRET };
  const server = await new Promise((resolve) => {
    const instance = createGatewayApp({ db, config }).listen(0, '127.0.0.1', () => resolve(instance));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { db, baseUrl };
}

async function post(baseUrl, route, body, headers = {}) {
  const response = await fetch(`${baseUrl}${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body)
  });
  const data = response.status === 204 ? null : await response.json();
  return { response, data };
}

async function login(baseUrl, username = 'mhs1', password = 'MhsSatu!2026', deviceId = 'device-mhs1-001') {
  return post(baseUrl, '/auth/login', { username, password }, { 'X-Device-ID': deviceId });
}

test('login valid menerbitkan access dan refresh token yang ditandatangani/disimpan sebagai hash', async (t) => {
  const { db, baseUrl } = await setup(t);
  const { response, data } = await login(baseUrl);
  assert.equal(response.status, 200);
  const claims = verifyToken(data.access_token, { secret: JWT_SECRET, expectedType: 'user' });
  assert.equal(claims.sub, '4');
  assert.equal(claims.role, 'mahasiswa');
  assert.equal(data.expires_in, 600);
  assert.equal(data.refresh_expires_in, 86400);
  const stored = db.prepare('SELECT token_hash, expires_at FROM refresh_tokens').get();
  assert.equal(stored.token_hash, hashRefreshToken(data.refresh_token));
  assert.notEqual(stored.token_hash, data.refresh_token);
  assert.ok(Date.parse(stored.expires_at) > Date.now());
});

test('login menolak password salah tanpa membocorkan keberadaan akun', async (t) => {
  const { baseUrl } = await setup(t);
  const known = await login(baseUrl, 'mhs1', 'wrong-password');
  const unknown = await login(baseUrl, 'unknown-user', 'wrong-password');
  assert.equal(known.response.status, 401);
  assert.equal(unknown.response.status, 401);
  assert.deepEqual(known.data, unknown.data);
});

test('login menolak device tidak terdaftar dan device milik akun lain', async (t) => {
  const { baseUrl } = await setup(t);
  const unknownDevice = await login(baseUrl, 'mhs1', 'MhsSatu!2026', 'unregistered-device');
  const otherUsersDevice = await login(baseUrl, 'mhs1', 'MhsSatu!2026', 'device-mhs2-001');
  assert.equal(unknownDevice.response.status, 401);
  assert.equal(otherUsersDevice.response.status, 401);
  assert.deepEqual(unknownDevice.data, otherUsersDevice.data);
});

test('access token valid diverifikasi dengan klaim pengguna yang benar', async (t) => {
  const { baseUrl } = await setup(t);
  const { data } = await login(baseUrl);
  const claims = verifyToken(data.access_token, { secret: JWT_SECRET, expectedType: 'user', allowedRoles: ['mahasiswa'] });
  assert.equal(claims.sub, '4');
  assert.equal(claims.typ, 'user');
});

test('access token kedaluwarsa ditolak', () => {
  const expired = jwt.sign({ sub: '4', role: 'mahasiswa', typ: 'user', iat: 100, exp: 101 }, JWT_SECRET, {
    algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, noTimestamp: true
  });
  assert.throws(() => verifyToken(expired, { secret: JWT_SECRET, expectedType: 'user', clockTimestamp: 102 }));
});

test('refresh valid merotasi token; token lama tidak dapat digunakan kembali', async (t) => {
  const { db, baseUrl } = await setup(t);
  const initial = await login(baseUrl);
  const refreshed = await post(baseUrl, '/auth/refresh', { refreshToken: initial.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(refreshed.response.status, 200);
  assert.notEqual(refreshed.data.refresh_token, initial.data.refresh_token);
  assert.equal(verifyToken(refreshed.data.access_token, { secret: JWT_SECRET, expectedType: 'user' }).role, 'mahasiswa');
  const oldRow = db.prepare('SELECT revoked_at FROM refresh_tokens WHERE token_hash=?').get(hashRefreshToken(initial.data.refresh_token));
  assert.ok(oldRow.revoked_at);
  const reuse = await post(baseUrl, '/auth/refresh', { refreshToken: initial.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(reuse.response.status, 401);
});

test('refresh token yang dicabut atau kedaluwarsa ditolak', async (t) => {
  const { db, baseUrl } = await setup(t);
  const revokedLogin = await login(baseUrl);
  db.prepare("UPDATE refresh_tokens SET revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE token_hash=?")
    .run(hashRefreshToken(revokedLogin.data.refresh_token));
  const revoked = await post(baseUrl, '/auth/refresh', { refreshToken: revokedLogin.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(revoked.response.status, 401);

  const expiredLogin = await login(baseUrl);
  db.prepare("UPDATE refresh_tokens SET expires_at='2000-01-01T00:00:00.000Z' WHERE token_hash=?")
    .run(hashRefreshToken(expiredLogin.data.refresh_token));
  const expired = await post(baseUrl, '/auth/refresh', { refreshToken: expiredLogin.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(expired.response.status, 401);
});

test('logout mencabut refresh token dan token tersebut tidak bisa refresh', async (t) => {
  const { db, baseUrl } = await setup(t);
  const initial = await login(baseUrl);
  const loggedOut = await post(baseUrl, '/auth/logout', { refreshToken: initial.data.refresh_token });
  assert.equal(loggedOut.response.status, 204);
  const stored = db.prepare('SELECT revoked_at FROM refresh_tokens WHERE token_hash=?').get(hashRefreshToken(initial.data.refresh_token));
  assert.ok(stored.revoked_at);
  const refresh = await post(baseUrl, '/auth/refresh', { refreshToken: initial.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(refresh.response.status, 401);
});

test('kredensial service valid menghasilkan token service berumur lima menit', async (t) => {
  const { baseUrl } = await setup(t);
  const result = await post(baseUrl, '/auth/service', { clientId: SERVICE_CLIENT_ID, clientSecret: SERVICE_CLIENT_SECRET });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.expires_in, 300);
  const claims = verifyToken(result.data.access_token, { secret: JWT_SECRET, expectedType: 'service', allowedRoles: ['service'] });
  assert.equal(claims.sub, 'grade-service');
  assert.deepEqual(claims.scope, ['transcript:sync']);
  assert.equal(Object.hasOwn(result.data, 'clientSecret'), false);
});

test('kredensial service salah ditolak', async (t) => {
  const { baseUrl } = await setup(t);
  const result = await post(baseUrl, '/auth/service', { clientId: SERVICE_CLIENT_ID, clientSecret: 'wrong-secret' });
  assert.equal(result.response.status, 401);
  assert.equal(JSON.stringify(result.data).includes(SERVICE_CLIENT_SECRET), false);
});

test('event auth mencatat endpoint, subject, device, hasil, dan alasan tanpa token atau rahasia', async (t) => {
  const { db, baseUrl } = await setup(t);
  const firstLogin = await login(baseUrl);
  assert.equal(firstLogin.response.status, 200);
  const refreshed = await post(baseUrl, '/auth/refresh', { refreshToken: firstLogin.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(refreshed.response.status, 200);
  const loggedOut = await post(baseUrl, '/auth/logout', { refreshToken: refreshed.data.refresh_token }, { 'X-Device-ID': 'device-mhs1-001' });
  assert.equal(loggedOut.response.status, 204);
  const deniedLogin = await login(baseUrl, 'mhs1', 'wrong-password', 'unregistered-device');
  assert.equal(deniedLogin.response.status, 401);
  const serviceIssued = await post(baseUrl, '/auth/service', { clientId: SERVICE_CLIENT_ID, clientSecret: SERVICE_CLIENT_SECRET });
  assert.equal(serviceIssued.response.status, 200);
  const serviceDenied = await post(baseUrl, '/auth/service', { clientId: SERVICE_CLIENT_ID, clientSecret: 'wrong-secret' });
  assert.equal(serviceDenied.response.status, 401);

  const events = db.prepare(`SELECT subject_id, subject_type, endpoint, device_id, result, reason
    FROM audit_logs ORDER BY id`).all();
  const loginAllow = events.find((event) => event.endpoint === 'POST /auth/login' && event.result === 'allow');
  const refreshAllow = events.find((event) => event.endpoint === 'POST /auth/refresh' && event.result === 'allow');
  const logoutAllow = events.find((event) => event.endpoint === 'POST /auth/logout' && event.result === 'allow');
  const loginDeny = events.find((event) => event.endpoint === 'POST /auth/login' && event.result === 'deny');
  const serviceAllow = events.find((event) => event.endpoint === 'POST /auth/service' && event.result === 'allow');
  const serviceDeny = events.find((event) => event.endpoint === 'POST /auth/service' && event.result === 'deny');
  assert.equal(loginAllow.subject_type, 'user');
  assert.equal(loginAllow.device_id, 'device-mhs1-001');
  assert.equal(refreshAllow.subject_id, 4);
  assert.equal(refreshAllow.device_id, 'device-mhs1-001');
  assert.equal(logoutAllow.subject_id, 4);
  assert.equal(loginDeny.device_id, 'unregistered-device');
  assert.equal(serviceAllow.subject_type, 'service:grade-service');
  assert.equal(serviceDeny.subject_type, 'anonymous');
  const serializedEvents = JSON.stringify(events);
  for (const sensitive of [JWT_SECRET, SERVICE_CLIENT_SECRET, firstLogin.data.access_token, firstLogin.data.refresh_token, refreshed.data.access_token, refreshed.data.refresh_token, 'wrong-password']) {
    assert.equal(serializedEvents.includes(sensitive), false);
  }
});

test('token pengguna tidak lolos validasi khusus service', async (t) => {
  const { baseUrl } = await setup(t);
  const { data } = await login(baseUrl);
  assert.throws(() => verifyToken(data.access_token, { secret: JWT_SECRET, expectedType: 'service', allowedRoles: ['service'] }));
});

test('token dengan signature tidak valid ditolak', () => {
  const token = jwt.sign({ sub: '4', role: 'mahasiswa', typ: 'user' }, OTHER_SECRET, {
    algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, expiresIn: 60
  });
  assert.throws(() => verifyToken(token, { secret: JWT_SECRET, expectedType: 'user' }));
});

test('middleware token reusable mengikat user token ke device terdaftar', async (t) => {
  const { db, baseUrl } = await setup(t);
  const { createTokenMiddleware } = require('../src/auth/middleware');
  const { data } = await login(baseUrl);
  const protectedApp = express();
  protectedApp.get('/protected', createTokenMiddleware({ secret: JWT_SECRET, expectedType: 'user', db, requireDevice: true }), (req, res) => {
    res.json({ subject: req.auth.sub, role: req.auth.role });
  });
  const server = await new Promise((resolve) => {
    const instance = protectedApp.listen(0, '127.0.0.1', () => resolve(instance));
  });
  t.after(() => new Promise((resolve, reject) => server.close((err) => err ? reject(err) : resolve())));
  const url = `http://127.0.0.1:${server.address().port}/protected`;
  const valid = await fetch(url, { headers: { authorization: `Bearer ${data.access_token}`, 'X-Device-ID': 'device-mhs1-001' } });
  const invalidDevice = await fetch(url, { headers: { authorization: `Bearer ${data.access_token}`, 'X-Device-ID': 'device-mhs2-001' } });
  const missingDevice = await fetch(url, { headers: { authorization: `Bearer ${data.access_token}` } });
  assert.equal(valid.status, 200);
  assert.deepEqual(await valid.json(), { subject: '4', role: 'mahasiswa' });
  assert.equal(invalidDevice.status, 401);
  assert.equal(missingDevice.status, 401);
});
