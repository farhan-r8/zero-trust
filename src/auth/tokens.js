const jwt = require('jsonwebtoken');

const ISSUER = 'zero-trust-security';
const AUDIENCE = 'zero-trust-api';
const ACCESS_TTL_SECONDS = 10 * 60;
const SERVICE_TTL_SECONDS = 5 * 60;

function requireJwtSecret(secret) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('JWT_SECRET harus dikonfigurasi dengan minimal 32 byte acak');
  }
  return secret;
}

function signToken(claims, secret, expiresIn) {
  return jwt.sign(claims, requireJwtSecret(secret), {
    algorithm: 'HS256',
    expiresIn,
    issuer: ISSUER,
    audience: AUDIENCE
  });
}

function createAccessToken(user, secret) {
  return signToken({ sub: String(user.id), role: user.role, typ: 'user' }, secret, ACCESS_TTL_SECONDS);
}

function createServiceToken(secret) {
  return signToken({ sub: 'grade-service', role: 'service', typ: 'service', scope: ['transcript:sync'] }, secret, SERVICE_TTL_SECONDS);
}

function verifyToken(token, { secret, expectedType, allowedRoles, clockTimestamp } = {}) {
  if (typeof token !== 'string' || token.length === 0) throw new Error('Token tidak valid');
  const claims = jwt.verify(token, requireJwtSecret(secret), {
    algorithms: ['HS256'],
    issuer: ISSUER,
    audience: AUDIENCE,
    clockTimestamp
  });
  if (!claims || typeof claims !== 'object' || typeof claims.sub !== 'string' || typeof claims.role !== 'string') {
    throw new Error('Klaim token tidak valid');
  }
  if (expectedType && claims.typ !== expectedType) throw new Error('Jenis token tidak sesuai');
  if (allowedRoles && !allowedRoles.includes(claims.role)) throw new Error('Role token tidak diizinkan');
  if (claims.typ === 'service' && claims.role !== 'service') throw new Error('Klaim token service tidak valid');
  if (claims.typ === 'user' && !['admin', 'dosen', 'mahasiswa'].includes(claims.role)) throw new Error('Role token pengguna tidak valid');
  if (!['user', 'service'].includes(claims.typ)) throw new Error('Jenis token tidak valid');
  return claims;
}

module.exports = {
  ISSUER,
  AUDIENCE,
  ACCESS_TTL_SECONDS,
  SERVICE_TTL_SECONDS,
  createAccessToken,
  createServiceToken,
  verifyToken
};
