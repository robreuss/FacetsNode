# ADR 0012: Durable Device Sync Migration Cancellation

- **Status:** Accepted for the headless PostgreSQL transition primitive
- **Date:** 2026-08-25
- **Scope:** Exact source unfencing and imported-target retirement

## Decision

PostgreSQL consumes the complete Facets-authority-signed
`MigrationCancellationEvidence`; a bare cancellation Manifest is not enough.
The terminal Manifest must be live on first application, its exact preparation
is reconstructed at the historical overlap, and the domain-separated digest of
the complete cancellation evidence becomes the durable transition identity.

The two local roles unwind differently:

- The source becomes writable under the cancellation Manifest. Cancellation
  is valid either while it is still writable under the exact preparation or
  after it committed an exact migration export and entered `export_fenced`.
  A fenced source must match the immutable export's migration, deployments,
  authority revision, Manifest digest, and active fence before that pointer is
  cleared.
- A target that already imported the exact preparation becomes `retired`. Its
  immutable import must bind the same canonical preparation and exact source,
  target, and migration identities. The active import pointer is cleared, but
  copied semantic rows and immutable import evidence are deliberately retained
  and remain inaccessible behind the retired enforcement state.

Both transitions hold the scope-enforcement row `FOR UPDATE` in a serializable
transaction and atomically replace authority, write state, and exceptional
fence/import pointers. Immutable export and import records are audit evidence;
cancellation does not delete them or attempt storage reclamation.

## Retry boundary

An exact already-applied terminal state is recognized from the canonical signed
Manifest and complete cancellation-evidence digest before temporal validation.
It can therefore repair a database step after the signed evidence's initial
acceptance window. Changed evidence, a different local role, a non-exact
preparation, an unrelated export/import, or inconsistent active pointers fails
closed.

## Orchestration boundary

This checkpoint deliberately does not expose cancellation through HTTP or an
operator command. The headless coordinator persists a deployment-signed live
acceptance before changing either store, then advances BindingRegistry before
PostgreSQL so a crash leaves the source database fenced, or the target database
standby, rather than creating a stale writer. Startup validates all pending
cancellation journals and completes their exact idempotent registry/database
steps before general authority readiness.

Completed cancellation journals remain part of startup reconciliation while
their exact cancellation revision is still the current registry authority. This
closes the target race where an import began before registry cancellation but
committed a non-writable standby afterward. If such a row appears, startup
reapplies the exact cancellation and retires it. A later registry revision
supersedes the completed journal, so historical cancellation cannot overwrite a
new authorized migration.

Cancellation before target import may have no target PostgreSQL row to unwind;
the coordinator accepts that absence only on the authenticated target role and
still verifies the exact terminal registry identity. A missing source row or a
non-exact existing target row is an error. Artifact and blob reclamation remains
a separate retention operation. General startup readiness currently keeps a
cancelled target or source from serving as the active deployment; multi-tenant
terminal-scope availability requires a separate readiness-policy checkpoint.
The live PostgreSQL test is skipped unless
`FACETS_SERVER_TEST_DATABASE_URL` names a disposable database, and this ADR
makes no deployed migration claim.
