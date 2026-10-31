const path = require('node:path');
require('dotenv').config({ path: path.resolve(process.cwd(), '.env') });

function numberFromEnv(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`${name} harus berupa port integer 1-65535`);
  }
  return value;
}

function timeFromEnv(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(value)) {
    throw new Error(`${name} harus berformat HH:mm`);
  }
  return value;
}

function positiveIntFromEnv(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 120000) {
    throw new Error(`${name} harus berupa integer 1-120000`);
  }
  return value;
}

module.exports = Object.freeze({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  timeZone: process.env.APP_TIMEZONE ?? 'Asia/Jakarta',
  accessWindowStart: timeFromEnv('ACCESS_WINDOW_START', '07:00'),
  accessWindowEnd: timeFromEnv('ACCESS_WINDOW_END', '21:00'),
  ports: Object.freeze({
    gateway: numberFromEnv('GATEWAY_PORT', 3000),
    gradeService: numberFromEnv('GRADE_SERVICE_PORT', 3001),
    transcriptService: numberFromEnv('TRANSCRIPT_SERVICE_PORT', 3002)
  }),
  upstreamTimeoutMs: positiveIntFromEnv('UPSTREAM_TIMEOUT_MS', 5000),
  gatewayBaseUrl: process.env.GATEWAY_BASE_URL ?? 'http://127.0.0.1:3000',
  databasePath: path.resolve(process.cwd(), process.env.DATABASE_PATH ?? './data/zero-trust.sqlite'),
  logPath: path.resolve(process.cwd(), process.env.LOG_PATH ?? './logs/app.log'),
  gatewaySecret: process.env.GATEWAY_SECRET,
  jwtSecret: process.env.JWT_SECRET,
  serviceClientId: process.env.SERVICE_CLIENT_ID,
  serviceClientSecret: process.env.SERVICE_CLIENT_SECRET
});
