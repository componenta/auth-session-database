CREATE TABLE auth_session_subject_locks (
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    lock_version BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB;

CREATE TABLE auth_sessions (
    uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    credential_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    credential_generation INT UNSIGNED NOT NULL,
    authenticated_at DATETIME(6) NOT NULL,
    reauthenticated_at DATETIME(6) NULL,
    last_active_at DATETIME(6) NOT NULL,
    idle_expires_at DATETIME(6) NOT NULL,
    absolute_expires_at DATETIME(6) NOT NULL,
    evidence TEXT NOT NULL,
    reauthentication_evidence TEXT NULL,
    metadata TEXT NOT NULL,
    revoked_at DATETIME(6) NULL,
    revocation_reason VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    INDEX idx_auth_session_subject_active (
        subject_uuid,
        revoked_at,
        idle_expires_at,
        absolute_expires_at
    ),
    INDEX idx_auth_session_cleanup (revoked_at, idle_expires_at, absolute_expires_at)
) ENGINE=InnoDB;

CREATE TABLE auth_session_credential_tombstones (
    credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    credential_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    session_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    replaced_generation INT UNSIGNED NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_auth_session_tombstone_session (session_uuid),
    INDEX idx_auth_session_tombstone_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE auth_pre_authentication_transactions (
    uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    credential_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_token_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    INDEX idx_auth_pre_authentication_expiry (expires_at)
) ENGINE=InnoDB;
