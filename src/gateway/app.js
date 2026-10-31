const express = require('express');
const { createAuthRouter } = require('./auth-routes');
const { ACTIONS, createPolicyMiddleware } = require('../policy/engine');
const { createProxy } = require('./proxy');

function policy({ db, config, action, resourceResolver }) {
  return createPolicyMiddleware({ db, jwtSecret: config.jwtSecret, config, action, resourceResolver });
}

function createGatewayApp({ db, config }) {
  if (!db || !config) throw new Error('Database dan konfigurasi wajib diberikan');
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb', strict: true }));
  app.use('/auth', createAuthRouter({ db, config }));

  const gradeUrl = config.gradeServiceUrl ?? `http://127.0.0.1:${config.ports?.gradeService ?? 3001}`;
  const transcriptUrl = config.transcriptServiceUrl ?? `http://127.0.0.1:${config.ports?.transcriptService ?? 3002}`;
  const proxyOptions = { timeoutMs: config.upstreamTimeoutMs ?? 5000, gatewaySecret: config.gatewaySecret };

  app.get('/nilai', policy({ db, config, action: ACTIONS.GRADES_READ, resourceResolver: (req) => ({
    classId: req.query.classId,
    studentId: req.query.studentId,
    gradeId: req.query.gradeId
  }) }), createProxy({ ...proxyOptions, baseUrl: gradeUrl, targetPath: (req) => req.originalUrl }));
  app.put('/nilai/:id', policy({ db, config, action: ACTIONS.GRADES_UPDATE, resourceResolver: (req) => ({ gradeId: req.params.id }) }),
    createProxy({ ...proxyOptions, baseUrl: gradeUrl, targetPath: (req) => `/nilai/${encodeURIComponent(req.params.id)}` }));
  app.post('/kelas/:id/finalisasi', policy({ db, config, action: ACTIONS.GRADES_FINALIZE, resourceResolver: (req) => ({ classId: req.params.id }) }),
    createProxy({ ...proxyOptions, baseUrl: gradeUrl, targetPath: (req) => `/kelas/${encodeURIComponent(req.params.id)}/finalisasi` }));
  app.get('/transkrip/:nim', policy({ db, config, action: ACTIONS.TRANSCRIPTS_READ, resourceResolver: (req) => ({ nim: req.params.nim }) }),
    createProxy({ ...proxyOptions, baseUrl: transcriptUrl, targetPath: (req) => `/transkrip/${encodeURIComponent(req.params.nim)}` }));
  app.post('/transkrip/sinkron', policy({ db, config, action: ACTIONS.TRANSCRIPTS_SYNC, resourceResolver: (req) => ({ gradeId: req.body?.gradeId }) }),
    createProxy({ ...proxyOptions, baseUrl: transcriptUrl, targetPath: '/transkrip/sinkron' }));

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof SyntaxError && Object.prototype.hasOwnProperty.call(err, 'body')) {
      return res.status(400).json({ error: 'JSON tidak valid' });
    }
    return res.status(500).json({ error: 'Terjadi kesalahan internal' });
  });
  return app;
}

module.exports = { createGatewayApp };
