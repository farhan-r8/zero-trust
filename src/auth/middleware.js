const { verifyToken } = require('./tokens');

function bearerFromHeader(header) {
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+([^\s]+)$/i.exec(header);
  return match ? match[1] : null;
}

function createTokenMiddleware({ secret, expectedType, allowedRoles, db, requireDevice = false }) {
  return (req, res, next) => {
    try {
      const token = bearerFromHeader(req.get('authorization'));
      const claims = verifyToken(token, { secret, expectedType, allowedRoles });
      if (expectedType === 'user' && requireDevice) {
        const deviceId = req.get('x-device-id');
        if (!deviceId || !db) return res.status(401).json({ error: 'Autentikasi ditolak' });
        const registered = db.prepare(`SELECT 1 FROM devices d JOIN users u ON u.id=d.user_id
          WHERE u.id=? AND u.is_active=1 AND d.device_id=? AND d.is_active=1`).get(Number(claims.sub), deviceId);
        if (!registered) return res.status(401).json({ error: 'Autentikasi ditolak' });
      }
      req.auth = claims;
      return next();
    } catch {
      return res.status(401).json({ error: 'Autentikasi ditolak' });
    }
  };
}

module.exports = { bearerFromHeader, createTokenMiddleware };
