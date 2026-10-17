-- LuweiDev: binding explicit and unique; legacy resources stay unbound and denied.
CREATE TABLE luwei_session_binding (
  sandbox_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  external_user_id TEXT NOT NULL,
  external_project_id TEXT NOT NULL,
  external_workspace_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX luwei_session_binding_session_idx ON luwei_session_binding(session_id);
