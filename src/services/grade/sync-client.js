function upstreamError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

async function requestTranscriptSync({ config, gradeId, fetchImpl = fetch }) {
  const timeoutMs = config.upstreamTimeoutMs ?? 5000;
  const baseUrl = config.gatewayBaseUrl;
  const signal = () => AbortSignal.timeout(timeoutMs);
  let authResponse;
  try {
    authResponse = await fetchImpl(new URL('/auth/service', baseUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ clientId: config.serviceClientId, clientSecret: config.serviceClientSecret }),
      signal: signal()
    });
  } catch (error) {
    throw upstreamError(error?.name === 'TimeoutError' || error?.name === 'AbortError' ? 'upstream_timeout' : 'gateway_unavailable');
  }
  if (!authResponse.ok) throw upstreamError(authResponse.status >= 500 ? 'gateway_unavailable' : 'service_auth_rejected');

  let tokenPayload;
  try {
    tokenPayload = await authResponse.json();
  } catch {
    throw upstreamError('service_auth_response_invalid');
  }
  if (typeof tokenPayload.access_token !== 'string' || tokenPayload.expires_in !== 300) {
    throw upstreamError('service_auth_response_invalid');
  }

  let syncResponse;
  try {
    syncResponse = await fetchImpl(new URL('/transkrip/sinkron', baseUrl), {
      method: 'POST',
      headers: {
        authorization: `Bearer ${tokenPayload.access_token}`,
        'content-type': 'application/json',
        accept: 'application/json'
      },
      body: JSON.stringify({ gradeId }),
      signal: signal()
    });
  } catch (error) {
    throw upstreamError(error?.name === 'TimeoutError' || error?.name === 'AbortError' ? 'upstream_timeout' : 'gateway_unavailable');
  }
  if (!syncResponse.ok) throw upstreamError(syncResponse.status >= 500 ? 'transcript_unavailable' : 'transcript_sync_rejected');
  return true;
}

module.exports = { requestTranscriptSync };
