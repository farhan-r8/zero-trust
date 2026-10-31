const bcrypt = require('bcryptjs');

const demoUsers = [
  { username: 'admin', name: 'Administrator Demo', nim: null, role: 'admin', password: 'AdminDemo!2026', device: 'device-admin-001' },
  { username: 'dosen1', name: 'Dosen Satu', nim: null, role: 'dosen', password: 'DosenSatu!2026', device: 'device-dosen1-001' },
  { username: 'dosen2', name: 'Dosen Dua', nim: null, role: 'dosen', password: 'DosenDua!2026', device: 'device-dosen2-001' },
  { username: 'mhs1', name: 'Mahasiswa Satu', nim: '230001', role: 'mahasiswa', password: 'MhsSatu!2026', device: 'device-mhs1-001' },
  { username: 'mhs2', name: 'Mahasiswa Dua', nim: '230002', role: 'mahasiswa', password: 'MhsDua!2026', device: 'device-mhs2-001' },
  { username: 'mhs3', name: 'Mahasiswa Tiga', nim: '230003', role: 'mahasiswa', password: 'MhsTiga!2026', device: 'device-mhs3-001' }
];

function seedDatabase(db) {
  const insertUser = db.prepare(`INSERT INTO users (username, full_name, nim, password_hash, role)
    VALUES (@username, @name, @nim, @password_hash, @role)
    ON CONFLICT(username) DO UPDATE SET full_name=excluded.full_name, nim=excluded.nim,
    password_hash=excluded.password_hash, role=excluded.role`);
  const insertDevice = db.prepare(`INSERT INTO devices (user_id, device_id) VALUES (?, ?)
    ON CONFLICT(user_id, device_id) DO UPDATE SET is_active=1`);
  const insertClass = db.prepare(`INSERT INTO classes (class_code, class_name, lecturer_id) VALUES (?, ?, ?)
    ON CONFLICT(class_code) DO UPDATE SET class_name=excluded.class_name, lecturer_id=excluded.lecturer_id`);
  const insertEnrollment = db.prepare(`INSERT INTO enrollments (class_id, student_id) VALUES (?, ?)
    ON CONFLICT(class_id, student_id) DO NOTHING`);
  const insertGrade = db.prepare(`INSERT INTO grades (class_id, student_id, score, is_final, updated_by, updated_at)
    VALUES (?, ?, ?, 0, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    ON CONFLICT(class_id, student_id) DO NOTHING`);

  const seed = db.transaction(() => {
    for (const user of demoUsers) {
      insertUser.run({ ...user, password_hash: bcrypt.hashSync(user.password, 10) });
    }
    const userId = (username) => db.prepare('SELECT id FROM users WHERE username = ?').get(username).id;
    for (const user of demoUsers) insertDevice.run(userId(user.username), user.device);

    insertClass.run('KI-501', 'Keamanan Informasi', userId('dosen1'));
    insertClass.run('KI-502', 'Keamanan Jaringan', userId('dosen2'));
    const classId = (code) => db.prepare('SELECT id FROM classes WHERE class_code = ?').get(code).id;
    for (const student of ['mhs1', 'mhs2', 'mhs3']) {
      insertEnrollment.run(classId('KI-501'), userId(student));
      insertGrade.run(classId('KI-501'), userId(student), student === 'mhs1' ? 86 : null, userId('dosen1'));
    }
    for (const student of ['mhs2', 'mhs3']) {
      insertEnrollment.run(classId('KI-502'), userId(student));
      insertGrade.run(classId('KI-502'), userId(student), student === 'mhs2' ? 91 : null, userId('dosen2'));
    }
  });

  seed();
}

module.exports = { seedDatabase, demoUsers };
