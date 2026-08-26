# ADR 0010: Device Sync Source Fence and Artifact Recovery

- **Status:** Accepted for the headless prepared-source checkpoint
- **Date:** 2026-08-25
- **Scope:** Device Sync source snapshot materialization, write fencing, signing, and restart recovery

## Decision

FacetsNode has a headless source coordinator that creates migration evidence in
this order for one Device Sync scope:

1. validate the live Facets migration preparation, source deployment, and
   offered target deployment;
2. while PostgreSQL holds the scope-enforcement row in a repeatable-read
   transaction, stream the exact logical service state and blob inventory into
   private scratch files;
3. verify their byte counts, SHA-256 transfer digests, and combined state
   commitment, then atomically commit an unsigned source draft to file custody;
4. return the exact canonical snapshot payload to PostgreSQL, which stores it
   and changes the scope from writable to export-fenced in the same transaction;
5. stage that exact stored payload in the deployment binding registry and sign
   it once with the active source deployment key; and
6. promote the draft into signed transfer custody by another atomic directory
   commit.

No snapshot is signed before both the PostgreSQL write fence and binding-registry
fence are durable. The source coordinator does not activate the target, retire
the source, choose a network route, or expose migration operations over HTTP.

## Source artifact custody

Scratch files and drafts live beneath an owner-only `FileArtifactCustody` root.
Paths are derived only from authenticated principal, migration, snapshot, and
artifact UUIDs. The source draft contains the exact service-state bytes, blob
inventory, complete migration preparation, canonical unsigned snapshot payload,
and internal binding metadata. Every file and the staging directory are synced
before an atomic rename commits the draft.

The source draft is not authority and cannot be transferred as a signed
snapshot. Its purpose is to ensure that the database fence cannot commit while
the bytes named by its snapshot payload exist only in volatile memory. After
the deployment signature is durable, promotion re-reads and hashes the draft,
commits the final signed custody record, and removes the unsigned duplicate.
This checkpoint accepts exactly the service-state and blob-inventory artifacts;
snapshots naming onion, TLS, route, or other custody kinds fail rather than
signing evidence for bytes the coordinator does not manage.

Private modes, regular-file identity, exact evidence bytes, exact sizes, and
SHA-256 digests are revalidated on open. Symlinks, permissive files, conflicting
operation identities, changed evidence, and corrupted artifacts fail closed.

## Restart and temporal behavior

Caller-supplied write-fence, snapshot, and artifact UUIDs are durable operation
journal identities. PostgreSQL returns an exact previously fenced export without
running the materializer again. The binding registry likewise returns the one
persisted ECDSA signature byte-for-byte instead of producing a different valid
signature for the same payload.

Historical verification exists only to recover an already-fenced and
already-signed local operation after its target offer or snapshot expires. It
cannot invoke a fresh materializer or produce a new signature. A clock earlier
than the snapshot capture instant fails closed. Targets continue to use strict
`ValidatePreparedTransfer` at receipt time, so recovering expired local evidence
does not make an expired transfer acceptable.

The coordinator first revalidates exact draft custody on retry. If the draft is
absent or corrupt, it uses a read-only registry operation that can return only
an already-confirmed signature; it cannot create one. Exact final custody is
then required. This covers a crash or lost response after promotion removed the
draft without allowing missing artifact bytes to trigger a new signature.
Conflicting retries never rebuild state beneath an existing database fence.

## Failure boundaries

- Failure before source-draft commit leaves only removable private scratch.
- Failure after draft commit but before the PostgreSQL commit may leave an
  unsigned orphan draft. Startup reconciliation and bounded garbage collection
  remain future operational work.
- Failure after the PostgreSQL fence leaves the scope non-writable. An exact
  retry resumes registry fencing, signing, and promotion from durable evidence.
- Failure after signing but before promotion retains the exact draft and
  signature for recovery.
- Failure after final custody but before response returns the exact signed
  transfer on retry without re-export or re-signing.

## Claim boundary and remaining work

This checkpoint supports the headless claim that a Device Sync source can
materialize exact logical artifacts under its database lock, atomically fence
writes with their canonical state commitment, sign only the exact fenced
snapshot, and recover the same signed custody after restart.

It does not provide authenticated or resumable network artifact transfer,
onion-service-state custody, source-to-target orchestration, Facets-authorized
activation, source retirement, bounded rollback, cancellation cleanup, startup
garbage collection, operator commands, product UI, container cutover, physical
runtime evidence, Shared Spaces migration, or Compute Pool migration.

## Acceptance evidence

Focused tests cover initial materialization, exact final custody, restart-style
custody reopen, expired exact retry, byte-identical signature reuse after binding
registry reload, clock rollback rejection, conflicting operation IDs, corrupt
durable drafts, inconsistent exporter commitments, and refusal to create a new
export from expired preparation evidence. Repository-wide Go, race, vet,
executable, PostgreSQL, and deployment evidence are recorded separately at the
commit checkpoint.
