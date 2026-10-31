CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  nim TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'dosen', 'mahasiswa')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  CHECK ((role = 'mahasiswa' AND nim IS NOT NULL) OR (role != 'mahasiswa' AND nim IS NULL))
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (user_id, device_id)
);
CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY,
  class_code TEXT NOT NULL UNIQUE,
  class_name TEXT NOT NULL,
  lecturer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_classes_lecturer ON classes(lecturer_id);

CREATE TABLE IF NOT EXISTS enrollments (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  enrolled_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (class_id, student_id)
);
CREATE INDEX IF NOT EXISTS idx_enrollments_student ON enrollments(student_id);

CREATE TABLE IF NOT EXISTS grades (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE RESTRICT,
  student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  score REAL CHECK (score IS NULL OR (score >= 0 AND score <= 100)),
  is_final INTEGER NOT NULL DEFAULT 0 CHECK (is_final IN (0, 1)),
  updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  updated_at TEXT,
  finalized_at TEXT,
  UNIQUE (class_id, student_id),
  FOREIGN KEY (class_id, student_id) REFERENCES enrollments(class_id, student_id) ON DELETE RESTRICT,
  CHECK ((is_final = 0 AND finalized_at IS NULL) OR (is_final = 1 AND finalized_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_grades_student ON grades(student_id);

CREATE TABLE IF NOT EXISTS transcripts (
  id INTEGER PRIMARY KEY,
  grade_id INTEGER NOT NULL UNIQUE REFERENCES grades(id) ON DELETE RESTRICT,
  student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE RESTRICT,
  score REAL NOT NULL CHECK (score >= 0 AND score <= 100),
  synced_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE (student_id, class_id)
);
CREATE INDEX IF NOT EXISTS idx_transcripts_student ON transcripts(student_id);

CREATE TABLE IF NOT EXISTS sync_jobs (
  id INTEGER PRIMARY KEY,
  grade_id INTEGER NOT NULL UNIQUE REFERENCES grades(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'succeeded', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at TEXT,
  sanitized_error TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_sync_jobs_retry ON sync_jobs(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY,
  occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  subject_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  subject_type TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device_id TEXT,
  result TEXT NOT NULL CHECK (result IN ('allow', 'deny', 'error')),
  reason TEXT NOT NULL,
  request_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_logs(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs(subject_id);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_logs(request_id);
