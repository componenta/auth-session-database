CREATE TABLE auth_session_subject_locks (
    subject_uuid UUID PRIMARY KEY,
    lock_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE auth_sessions (
    uuid UUID PRIMARY KEY,
    subject_uuid UUID NOT NULL,
    credential_hash CHAR(64) NOT NULL UNIQUE,
    credential_key_id VARCHAR(64) NOT NULL,
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    authenticated_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    reauthenticated_at TIMESTAMP(6) WITHOUT TIME ZONE NULL,
    last_active_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    idle_expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    absolute_expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    evidence TEXT NOT NULL,
    reauthentication_evidence TEXT NULL,
    metadata TEXT NOT NULL,
    revoked_at TIMESTAMP(6) WITHOUT TIME ZONE NULL,
    revocation_reason VARCHAR(64) NULL
);

CREATE INDEX idx_auth_session_subject_active
    ON auth_sessions(subject_uuid, revoked_at, idle_expires_at, absolute_expires_at);
CREATE INDEX idx_auth_session_cleanup
    ON auth_sessions(revoked_at, idle_expires_at, absolute_expires_at);

CREATE TABLE auth_session_credential_tombstones (
    credential_hash CHAR(64) PRIMARY KEY,
    credential_key_id VARCHAR(64) NOT NULL,
    session_uuid UUID NOT NULL,
    replaced_generation INTEGER NOT NULL CHECK (replaced_generation > 0),
    expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL
);

CREATE INDEX idx_auth_session_tombstone_session
    ON auth_session_credential_tombstones(session_uuid);
CREATE INDEX idx_auth_session_tombstone_expiry
    ON auth_session_credential_tombstones(expires_at);

CREATE TABLE auth_pre_authentication_transactions (
    uuid UUID PRIMARY KEY,
    credential_hash CHAR(64) NOT NULL UNIQUE,
    credential_key_id VARCHAR(64) NOT NULL,
    request_token_hash CHAR(64) NOT NULL,
    request_token_key_id VARCHAR(64) NOT NULL,
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL
);

CREATE INDEX idx_auth_pre_authentication_expiry
    ON auth_pre_authentication_transactions(expires_at);
