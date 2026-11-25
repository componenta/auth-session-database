# Componenta Auth Session Database

Cycle Database persistence for `componenta/auth-session`.

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

A `touch()` at or before the observed activity time has no effect. Rotation uses
the later of the local clock and the loaded row's activity time, including when
the caller holds an older snapshot. This preserves the session's timeline across
clock skew without failing after a reauthentication proof has been consumed.
A reauthentication time ahead of the wall clock does not satisfy a freshness
requirement until that clock catches up. Non-reauthentication rotation still
cannot extend the absolute expiry.

This is the first stable schema for this package. Applications using an earlier
development snapshot must regenerate their application-owned schema migration
to remove `auth_sessions.created_at` before adopting the new adapter. Preserve
`authenticated_at` and all other session data. The package does not run migrations
or modify an application's database on installation.
