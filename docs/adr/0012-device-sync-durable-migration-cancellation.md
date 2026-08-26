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
operator command. BindingRegistry already applies the same exact cancellation,
but the two stores do not yet share a deployment-signed pending journal or
startup recovery path. A production coordinator must persist live acceptance
before changing either store, then advance BindingRegistry before PostgreSQL so
any crash remains non-writable rather than reopening a stale source.

Cancellation before target import may have no target PostgreSQL row to unwind;
the future coordinator must distinguish that legitimate absence from database
failure using its exact operation journal and registry state. Artifact and blob
reclamation remains a separate retention operation. The live PostgreSQL test is
skipped unless `FACETS_SERVER_TEST_DATABASE_URL` names a disposable database,
and this ADR makes no runtime or deployment claim.
