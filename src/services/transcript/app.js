const express = require('express');
const { ACTIONS, createPolicyMiddleware } = require('../../policy/engine');
const { gatewaySecretMiddleware } = require('../common/gateway-secret');

function createTranscriptServiceApp({ db, config }) {
  if (!db || !config) throw new Error('Database dan konfigurasi wajib diberikan');
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb', strict: true }));
  const gatewayOnly = gatewaySecretMiddleware(config.gatewaySecret, db, [config.jwtSecret, config.serviceClientSecret]);
  const policy = (action, resourceResolver) => createPolicyMiddleware({ db, jwtSecret: config.jwtSecret, config, action, resourceResolver });

  app.get('/transkrip/:nim', gatewayOnly,
    policy(ACTIONS.TRANSCRIPTS_READ, (req) => ({ nim: req.params.nim })),
    (req, res) => {
      const student = db.prepare("SELECT id, nim, full_name FROM users WHERE nim=? AND role='mahasiswa' AND is_active=1").get(req.params.nim);
      if (!student) return res.status(404).json({ error: 'Transkrip tidak ditemukan' });
      const transcript = db.prepare(`SELECT t.class_id AS classId, c.class_code AS classCode, c.class_name AS className,
        t.score, t.synced_at AS syncedAt FROM transcripts t JOIN classes c ON c.id=t.class_id
        WHERE t.student_id=? ORDER BY c.class_code`).all(student.id);
      return res.status(200).json({ nim: student.nim, studentName: student.full_name, data: transcript });
    });

  app.post('/transkrip/sinkron', gatewayOnly,
    policy(ACTIONS.TRANSCRIPTS_SYNC, (req) => ({ gradeId: req.body?.gradeId })),
    (req, res) => {
      const gradeId = Number(req.body.gradeId);
      const sync = db.transaction(() => {
        const grade = db.prepare(`SELECT g.id, g.class_id, g.student_id, g.score, g.is_final,
          u.nim, u.full_name FROM grades g JOIN users u ON u.id=g.student_id WHERE g.id=?`).get(gradeId);
        if (!grade || !grade.is_final || grade.score === null) return null;
        db.prepare(`INSERT INTO transcripts (grade_id, student_id, class_id, score)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(grade_id) DO UPDATE SET score=excluded.score, synced_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`)
          .run(grade.id, grade.student_id, grade.class_id, grade.score);
        return db.prepare(`SELECT id, grade_id AS gradeId, student_id AS studentId, class_id AS classId,
          score, synced_at AS syncedAt FROM transcripts WHERE grade_id=?`).get(grade.id);
      });

      try {
        const transcript = sync();
        if (!transcript) return res.status(409).json({ error: 'Nilai final tidak ditemukan' });
        return res.status(200).json({ data: transcript });
      } catch {
        return res.status(409).json({ error: 'Sinkronisasi bertentangan dengan data transkrip' });
      }
    });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof SyntaxError && Object.prototype.hasOwnProperty.call(err, 'body')) return res.status(400).json({ error: 'JSON tidak valid' });
    return res.status(500).json({ error: 'Terjadi kesalahan internal' });
  });
  return app;
}

function startTranscriptService({ db, config }) {
  if (!config.gatewaySecret || !config.jwtSecret || Buffer.byteLength(config.jwtSecret, 'utf8') < 32) {
    throw new Error('Konfigurasi rahasia Transcript Service belum lengkap');
  }
  const server = createTranscriptServiceApp({ db, config }).listen(config.ports.transcriptService, '127.0.0.1', () => {
    console.log(`Transcript Service berjalan pada port ${config.ports.transcriptService}`);
  });
  return server;
}

module.exports = { createTranscriptServiceApp, startTranscriptService };
