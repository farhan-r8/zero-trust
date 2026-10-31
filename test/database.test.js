const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { openDatabase } = require('../src/db/connection');
const { initializeDatabase } = require('../src/db/init');

test('schema, seed, foreign keys, constraints, dan seed ulang berjalan benar', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zero-trust-test-'));
  const dbPath = path.join(dir, 'test.sqlite');

  initializeDatabase(dbPath);
  initializeDatabase(dbPath);
  const db = openDatabase(dbPath);
  t.after(() => {
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
  for (const name of ['users', 'devices', 'refresh_tokens', 'classes', 'enrollments', 'grades', 'transcripts', 'sync_jobs', 'audit_logs']) {
    assert.ok(tables.includes(name), `tabel ${name} tersedia`);
  }
  assert.equal(db.pragma('foreign_keys', { simple: true }), 1);

  assert.equal(db.prepare("SELECT count(*) AS n FROM users WHERE role='admin'").get().n, 1);
  assert.equal(db.prepare("SELECT count(*) AS n FROM users WHERE role='dosen'").get().n, 2);
  assert.equal(db.prepare("SELECT count(*) AS n FROM users WHERE role='mahasiswa'").get().n, 3);
  assert.equal(db.prepare('SELECT count(*) AS n FROM classes').get().n, 2);
  assert.equal(db.prepare('SELECT count(DISTINCT lecturer_id) AS n FROM classes').get().n, 2);
  assert.equal(db.prepare("SELECT count(*) AS n FROM classes c JOIN users u ON u.id=c.lecturer_id WHERE u.role='dosen'").get().n, 2);
  assert.equal(db.prepare('SELECT count(*) AS n FROM devices').get().n, 6);
  assert.equal(db.prepare('SELECT count(*) AS n FROM users u WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.user_id=u.id AND d.is_active=1)').get().n, 0);
  assert.equal(db.prepare('SELECT count(*) AS n FROM enrollments').get().n, 5);
  assert.equal(db.prepare('SELECT count(*) AS n FROM grades').get().n, 5);
  assert.ok(db.prepare('SELECT count(*) AS n FROM grades WHERE score IS NOT NULL').get().n >= 1);

  const hashes = db.prepare('SELECT password_hash FROM users').all();
  assert.equal(hashes.length, 6);
  assert.ok(hashes.every(({ password_hash }) => /^\$2[aby]\$/.test(password_hash)));
  assert.ok(bcrypt.compareSync('AdminDemo!2026', db.prepare("SELECT password_hash FROM users WHERE username='admin'").get().password_hash));

  assert.throws(() => db.prepare('INSERT INTO enrollments (class_id, student_id) VALUES (1, 4)').run(), /UNIQUE constraint failed/);
  assert.throws(() => db.prepare("INSERT INTO devices (user_id, device_id) VALUES (99999, 'orphan')").run(), /FOREIGN KEY constraint failed/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM users').get().n, 6);
  assert.equal(db.prepare('SELECT count(*) AS n FROM classes').get().n, 2);
  assert.equal(db.prepare('SELECT count(*) AS n FROM devices').get().n, 6);
  assert.equal(db.prepare('SELECT count(*) AS n FROM enrollments').get().n, 5);
  assert.equal(db.prepare('SELECT count(*) AS n FROM grades').get().n, 5);
});
