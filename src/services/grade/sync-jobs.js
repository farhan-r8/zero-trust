const { requestTranscriptSync } = require('./sync-client');

let workerActive = false;

function recoverProcessingJobs(db) {
  db.prepare(`UPDATE sync_jobs SET status='pending', next_attempt_at=NULL,
    sanitized_error='worker_recovered', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE status='processing'`).run();
}

function retryDelayMs(attempt) {
  return Math.min(1000 * (2 ** Math.min(attempt, 10)), 15 * 60 * 1000);
}

async function processSyncJobs({ db, config, gradeIds, fetchImpl }) {
  if (workerActive) return [];
  workerActive = true;
  const outcomes = [];
  try {
    const ids = Array.isArray(gradeIds) ? gradeIds.filter((id) => Number.isSafeInteger(id) && id > 0) : null;
    const whereId = ids ? ` AND j.grade_id IN (${ids.length ? ids.map(() => '?').join(',') : 'NULL'})` : '';
    const pending = db.prepare(`SELECT j.id, j.grade_id, j.attempts FROM sync_jobs j
      JOIN grades g ON g.id=j.grade_id
      WHERE j.status IN ('pending','failed') AND (j.next_attempt_at IS NULL OR j.next_attempt_at<=?)
      AND g.is_final=1 AND g.score IS NOT NULL${whereId} ORDER BY j.id`)
      .all(new Date().toISOString(), ...(ids ?? []));

    for (const job of pending) {
      const claim = db.prepare(`UPDATE sync_jobs SET status='processing', attempts=attempts+1,
        updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND status IN ('pending','failed')`).run(job.id);
      if (claim.changes !== 1) continue;
      const attempt = job.attempts + 1;
      try {
        await requestTranscriptSync({ config, gradeId: job.grade_id, fetchImpl });
        db.prepare(`UPDATE sync_jobs SET status='succeeded', next_attempt_at=NULL, sanitized_error=NULL,
          updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`).run(job.id);
        outcomes.push({ gradeId: job.grade_id, status: 'succeeded' });
      } catch (error) {
        const code = ['upstream_timeout', 'gateway_unavailable', 'service_auth_rejected', 'service_auth_response_invalid', 'transcript_unavailable', 'transcript_sync_rejected'].includes(error?.code)
          ? error.code
          : 'sync_failed';
        const nextAttempt = new Date(Date.now() + retryDelayMs(attempt)).toISOString();
        db.prepare(`UPDATE sync_jobs SET status='pending', next_attempt_at=?, sanitized_error=?,
          updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`).run(nextAttempt, code, job.id);
        outcomes.push({ gradeId: job.grade_id, status: 'pending' });
      }
    }
    return outcomes;
  } finally {
    workerActive = false;
  }
}

module.exports = { processSyncJobs, recoverProcessingJobs, retryDelayMs };
