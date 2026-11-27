# Componenta Auth Session Database

Cycle Database persistence for `componenta/auth-session`.

Version 2 requires `componenta/auth ^4.0.0`, `componenta/auth-session ^2.0.0`
and `componenta/identity ^1.1.1`.

Security properties:

- raw `SessionCredential` values are never stored;
- credential lookup uses domain-separated HMAC-SHA-256 with key IDs;
- rotation updates one stable session UUID/generation atomically;
- replaced credential hashes become short-lived revocation-only tombstones;
- tombstones never authenticate and exist only for stale logout/revocation races;
- create/revoke-all operations serialize through a per-subject lock row.

## Authentication timestamps and schema

The installation schemas use `authenticated_at` as the initial login time.
The session model, persistence, and oldest-session ordering all use this value;
credential rotation preserves it. There is no `auth_sessions.created_at` column.
The independent `created_at` of pre-authentication transactions is retained.

A delayed `touch()` cannot renew an expired session. Its conditional UPDATE is
checked against the original idle and absolute deadlines before commit; a late
write rolls back its own transaction or savepoint, preserving the caller's other
changes. A renewal accepted before the old deadline remains valid if the COMMIT
acknowledgment arrives later. This adds transaction control without another SELECT.

Rotation also rechecks the loaded session's original idle and absolute deadlines
after its UPDATE, before commit. A late write throws `InvalidArgumentException`
and rolls back both the new credential generation and its revocation tombstone.
The caller's outer transaction is preserved through a savepoint. A timely
rotation remains valid if only the COMMIT acknowledgment is delayed; the check
adds no SQL queries and does not extend the lifetime of an expired session.

A `touch()` at or before the observed activity time has no effect. Rotation uses
the later of the local clock and the loaded row's activity time, including when
the caller holds an older snapshot. This preserves the session's timeline across
clock skew without failing after a reauthentication proof has been consumed.
A reauthentication time ahead of the wall clock does not satisfy a freshness
requirement until that clock catches up. Non-reauthentication rotation still
cannot extend the absolute expiry.

Version 2 retains the schema published with version 1. Applications using a
pre-1.0 development snapshot must update their application-owned schema migration
to remove `auth_sessions.created_at`. Preserve `authenticated_at` and all other
session data. The package does not run migrations or modify an application's
database on installation.

Pre-authentication consumption rejects a proof that expires while its atomic
claim is waiting for the database. Such a proof cannot authorize the caller even
when the request began before its expiry.
