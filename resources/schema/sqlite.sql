CREATE TABLE auth_session_subject_locks (
    subject_uuid TEXT PRIMARY KEY,
    lock_version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE auth_sessions (
    uuid TEXT PRIMARY KEY,
    subject_uuid TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    credential_key_id TEXT NOT NULL,
    credential_generation INTEGER NOT NULL,
    authenticated_at TEXT NOT NULL,
    reauthenticated_at TEXT NULL,
    last_active_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    evidence TEXT NOT NULL,
    reauthentication_evidence TEXT NULL,
    metadata TEXT NOT NULL,
    revoked_at TEXT NULL,
    revocation_reason TEXT NULL
);

CREATE INDEX auth_sessions_subject_active
    ON auth_sessions(subject_uuid, revoked_at, idle_expires_at, absolute_expires_at);

CREATE TABLE auth_session_credential_tombstones (
    credential_hash TEXT PRIMARY KEY,
    credential_key_id TEXT NOT NULL,
    session_uuid TEXT NOT NULL,
    replaced_generation INTEGER NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX auth_session_tombstone_session
    ON auth_session_credential_tombstones(session_uuid);
CREATE INDEX auth_session_tombstone_expiry
    ON auth_session_credential_tombstones(expires_at);


CREATE TABLE auth_pre_authentication_transactions (
    uuid TEXT PRIMARY KEY,
    credential_hash TEXT NOT NULL UNIQUE,
    credential_key_id TEXT NOT NULL,
    request_token_hash TEXT NOT NULL,
    request_token_key_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX auth_pre_authentication_expiry
    ON auth_pre_authentication_transactions(expires_at);
