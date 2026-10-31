function createProxy({ baseUrl, targetPath, timeoutMs = 5000, gatewaySecret }) {
  return async (req, res) => {
    if (!gatewaySecret) return res.status(503).json({ error: 'Layanan upstream belum dikonfigurasi' });
    const headers = { 'x-gateway-secret': gatewaySecret, accept: 'application/json' };
    const authorization = req.get('authorization');
    const deviceId = req.get('x-device-id');
    if (authorization) headers.authorization = authorization;
    if (deviceId) headers['x-device-id'] = deviceId;
    const options = { method: req.method, headers, signal: AbortSignal.timeout(timeoutMs) };
    if (!['GET', 'HEAD'].includes(req.method)) {
      headers['content-type'] = 'application/json';
      options.body = JSON.stringify(req.body ?? {});
    }

    try {
      const resolvedPath = typeof targetPath === 'function' ? targetPath(req) : targetPath;
      const response = await fetch(new URL(resolvedPath, baseUrl), options);
      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.toLowerCase().includes('application/json')) {
        return res.status(502).json({ error: 'Respons upstream tidak valid' });
      }
      const payload = await response.json();
      return res.status(response.status).json(payload);
    } catch (error) {
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        return res.status(504).json({ error: 'Layanan upstream timeout' });
      }
      return res.status(503).json({ error: 'Layanan upstream tidak tersedia' });
    }
  };
}

module.exports = { createProxy };
