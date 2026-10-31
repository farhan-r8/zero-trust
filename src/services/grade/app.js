const express = require('express');
const { ACTIONS, createPolicyMiddleware } = require('../../policy/engine');
const { gatewaySecretMiddleware } = require('../common/gateway-secret');
const { processSyncJobs, recoverProcessingJobs } = require('./sync-jobs');

function createGradeServiceApp({ db, config, syncJobs = processSyncJobs }) {
  if (!db || !config) throw new Error('Database dan konfigurasi wajib diberikan');
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb', strict: true }));
  const gatewayOnly = gatewaySecretMiddleware(config.gatewaySecret, db, [config.jwtSecret, config.serviceClientSecret]);
  const policy = (action, resourceResolver) => createPolicyMiddleware({ db, jwtSecret: config.jwtSecret, config, action, resourceResolver });

  app.get('/nilai', gatewayOnly,
    policy(ACTIONS.GRADES_READ, (req) => ({ classId: req.query.classId, studentId: req.query.studentId, gradeId: req.query.gradeId })),
    (req, res) => {
      const clauses = [];
      const params = [];
      if (req.auth.role === 'mahasiswa') {
        clauses.push('g.student_id=?');
        params.push(Number(req.auth.sub));
      } else if (req.auth.role === 'dosen') {
        if (req.query.classId !== undefined) {
          clauses.push('g.class_id=?');
          params.push(Number(req.query.classId));
        } else if (req.query.gradeId !== undefined) {
          clauses.push('g.id=?', 'c.lecturer_id=?');
          params.push(Number(req.query.gradeId), Number(req.auth.sub));
        } else {
          return res.status(403).json({ error: 'Akses ditolak' });
        }
      } else {
        return res.status(403).json({ error: 'Akses ditolak' });
      }
      if (req.query.classId !== undefined && req.auth.role === 'mahasiswa') {
        clauses.push('g.class_id=?');
        params.push(Number(req.query.classId));
      }
      if (req.query.gradeId !== undefined) {
        clauses.push('g.id=?');
        params.push(Number(req.query.gradeId));
      }
      const values = db.prepare(`SELECT g.id, c.id AS classId, c.class_code AS classCode, c.class_name AS className,
        s.nim, s.full_name AS studentName, g.score, g.is_final AS isFinal, g.updated_at AS updatedAt, g.finalized_at AS finalizedAt
        FROM grades g JOIN classes c ON c.id=g.class_id JOIN users s ON s.id=g.student_id
        WHERE ${clauses.join(' AND ')} ORDER BY c.class_code, s.nim`).all(...params);
      return res.status(200).json({ data: values });
    });

  app.put('/nilai/:id', gatewayOnly,
    policy(ACTIONS.GRADES_UPDATE, (req) => ({ gradeId: req.params.id })),
    (req, res) => {
      const score = req.body?.score;
      if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 100) {
        return res.status(400).json({ error: 'Nilai harus berupa angka 0 sampai 100' });
      }
      const result = db.prepare(`UPDATE grades SET score=?, updated_by=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id=? AND is_final=0 AND EXISTS
          (SELECT 1 FROM classes c WHERE c.id=grades.class_id AND c.lecturer_id=?)`)
        .run(score, Number(req.auth.sub), Number(req.params.id), Number(req.auth.sub));
      if (result.changes !== 1) return res.status(409).json({ error: 'Nilai tidak dapat diubah' });
      const grade = db.prepare('SELECT id, class_id AS classId, student_id AS studentId, score, is_final AS isFinal FROM grades WHERE id=?').get(Number(req.params.id));
      return res.status(200).json({ data: grade });
    });

  app.post('/kelas/:id/finalisasi', gatewayOnly,
    policy(ACTIONS.GRADES_FINALIZE, (req) => ({ classId: req.params.id })),
    async (req, res) => {
      const classId = Number(req.params.id);
      const lecturerId = Number(req.auth.sub);
      const finalize = db.transaction(() => {
        const classroom = db.prepare('SELECT id FROM classes WHERE id=? AND lecturer_id=?').get(classId, lecturerId);
        if (!classroom) return { error: 'class_not_assigned' };
        const grades = db.prepare('SELECT id, score FROM grades WHERE class_id=? ORDER BY id').all(classId);
        if (!grades.length) return { error: 'class_has_no_grades' };
        if (grades.some((grade) => grade.score === null)) return { error: 'class_has_incomplete_grades' };
        const finalizedAt = new Date().toISOString();
        db.prepare(`UPDATE grades SET is_final=1, finalized_at=COALESCE(finalized_at,?), updated_by=?,
          updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE class_id=? AND is_final=0`).run(finalizedAt, lecturerId, classId);
        const addJob = db.prepare(`INSERT INTO sync_jobs (grade_id, status, attempts) VALUES (?, 'pending', 0)
          ON CONFLICT(grade_id) DO NOTHING`);
        for (const grade of grades) addJob.run(grade.id);
        return { gradeIds: grades.map((grade) => grade.id) };
      });
      const result = finalize();
      if (result.error) return res.status(409).json({ error: result.error });
      const syncResults = await syncJobs({ db, config, gradeIds: result.gradeIds });
      const placeholders = result.gradeIds.map(() => '?').join(',');
      const statuses = db.prepare(`SELECT status, COUNT(*) AS count FROM sync_jobs WHERE grade_id IN (${placeholders}) GROUP BY status`).all(...result.gradeIds);
      const pending = statuses.some((row) => row.status !== 'succeeded');
      return res.status(pending ? 202 : 200).json({
        finalized: true,
        sync: { status: pending ? 'pending' : 'succeeded', results: syncResults }
      });
    });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof SyntaxError && Object.prototype.hasOwnProperty.call(err, 'body')) return res.status(400).json({ error: 'JSON tidak valid' });
    return res.status(500).json({ error: 'Terjadi kesalahan internal' });
  });
  return app;
}

function startGradeService({ db, config }) {
  if (!config.gatewaySecret || !config.jwtSecret || Buffer.byteLength(config.jwtSecret, 'utf8') < 32 ||
      !config.serviceClientId || !config.serviceClientSecret) {
    throw new Error('Konfigurasi rahasia Grade Service belum lengkap');
  }
  recoverProcessingJobs(db);
  const server = createGradeServiceApp({ db, config }).listen(config.ports.gradeService, '127.0.0.1', () => {
    console.log(`Grade Service berjalan pada port ${config.ports.gradeService}`);
  });
  const timer = setInterval(() => {
    processSyncJobs({ db, config }).catch(() => {});
  }, 5000);
  timer.unref();
  return { server, timer };
}

module.exports = { createGradeServiceApp, startGradeService };
