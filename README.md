# Componenta Auth Session Database

Cycle Database persistence for `componenta/auth-session`.

Security properties:

- raw `SessionCredential` values are never stored;
- credential lookup uses domain-separated HMAC-SHA-256 with key IDs;
- rotation updates one stable session UUID/generation atomically;
- replaced credential hashes become short-lived revocation-only tombstones;
- tombstones never authenticate and exist only for stale logout/revocation races;
- create/revoke-all operations serialize through a per-subject lock row.
