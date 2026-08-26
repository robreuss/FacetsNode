# ADR 0011: Durable Device Sync Migration Activation

- **Status:** Accepted for the headless database cutover primitive
- **Date:** 2026-08-25
- **Scope:** Exact target activation and source write retirement

## Decision

PostgreSQL consumes the complete Facets-authorized
`MigrationActivationEvidence`; it does not accept a bare activation Manifest or
caller-supplied authority identity. The exact evidence is historically
validated, its terminal Manifest must remain live on first application, and the
domain-separated digest of the complete evidence becomes the durable
transition-evidence identity.

The two local deployment roles have different required predecessor states:

- The target must be the non-writable standby created by the exact immutable
  migration import. Its canonical preparation record, signed snapshot record,
  snapshot and fence identities, and state commitment must match the activation
  evidence byte for byte. Activation clears the exceptional import pointer and
  makes the target writable under the activation Manifest.
- The source must be durably `export_fenced` by the exact immutable export. Its
  canonical snapshot payload, snapshot and fence identities, deployments, and
  state commitment must match the activation evidence. Activation makes the
  source `retired`, clears the active database fence pointer, and leaves the
  immutable export evidence in place. The source therefore remains
  non-writable while the separately persisted BindingRegistry retains the
  signed forward fence needed by rollback authorization.

The transition holds the enforcement row `FOR UPDATE` in a serializable
transaction and updates authority, write state, and exceptional import/fence
pointers atomically. Deferred semantic-write triggers therefore cannot commit a
mutation across cutover.

## Retry and ordering boundary

An exact already-applied retry is recognized from the signed Manifest bytes and
the complete activation-evidence digest before time validation. It remains
recoverable after short-lived readiness or terminal evidence expires. Changed
evidence, another deployment role, a different imported snapshot, or a
different source export fails closed.

The headless local migration coordinator persists the exact activation evidence
and its live acceptance instant beside the already authenticated transfer,
advances BindingRegistry, and then invokes this database primitive. That order
cannot make two deployments writable: a database failure after registry
advancement leaves the target database standby or the source database fenced.

The owner-only journal is deployment-signed, written, and directory-synced
before either durable authority store changes. Its acceptance record binds the
local deployment, scope, migration, snapshot, exact activation-evidence digest,
and original live acceptance instant. A pending record is retained across
failure; `Recover` revalidates that signature, the complete evidence, its
canonical digest, the underlying transfer, and every private path before
repeating the two exact idempotent transitions. This permits recovery after
short-lived snapshot, readiness, or activation expiry without treating a bare
registry identity or a caller-supplied timestamp as sufficient evidence. Once
registry and database identities and write states agree, the journal is
atomically renamed to a completed audit record and no longer participates in
startup recovery. Clock rollback before the signed acceptance instant fails
closed.

## Claim boundary

This remains headless orchestration. Device Sync server construction opens a
`migration-custody` directory beside the persistent BindingRegistry and invokes
`Recover` before the general authority-readiness gate. A recovered target must
then pass the ordinary exact writable registry/database comparison before any
listener starts. A recovered source becomes durably retired and the ordinary
readiness gate still refuses to start it as a serving deployment.

No cutover route invokes this coordinator yet. It also does not coordinate two
hosts, stop an already-running old listener, move onion or TLS custody,
implement rollback/cancellation, or prove a deployed migration.
PostgreSQL integration executes only when a disposable
`FACETS_SERVER_TEST_DATABASE_URL` is configured; an unset live gate is a skip,
not runtime evidence.
