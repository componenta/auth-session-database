# Changelog

## Unreleased (2.0.0)

- Adopt Componenta Auth 4, Auth Session 2 and Identity 1.1.1.
- Reject pre-authentication proofs that expire during their conditional deletion.
- Roll back an activity renewal if its UPDATE completes after the observed
  session's idle or absolute deadline. Preserve generation/activity comparisons
  and the caller's outer transaction through a savepoint.
- Keep the version 1 database schema. See README for older development snapshots.
