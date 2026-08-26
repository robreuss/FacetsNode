# ADR 0009: Device Sync Target Custody and Readiness

- **Status:** Accepted for the headless prepared-target checkpoint
- **Date:** 2026-08-25
- **Scope:** Device Sync migration artifact custody, blob transfer, and target readiness

## Decision

FacetsNode has a headless target coordinator that will sign migration readiness
only after all of the following are true for one authenticated Device Sync
snapshot:

1. the exact service-state and blob-inventory streams are committed to private,
   durable local artifact custody;
2. every content-addressed encrypted blob named by the canonical inventory is
   copied and independently verified by the target blob store;
3. the exact logical state is imported and independently reproduced by the
   PostgreSQL migration importer; and
4. a second idempotent blob pass succeeds after the imported database rows have
   become authoritative.

The resulting deployment-signed readiness binds the migration, scope,
preparation-manifest digest, snapshot reference digest, importing deployment,
and applied state commitment. It remains evidence for a separately
Facets-authorized activation. The target coordinator cannot activate itself.

## Artifact custody

`FileArtifactCustody` derives paths only from authenticated principal,
migration, and snapshot UUIDs. A transfer is first written beneath an
owner-only staging directory. Artifact byte counts and SHA-256 transfer digests
must exactly equal the signed descriptors. The service-state artifact, blob
inventory, preparation evidence, snapshot evidence, and internal binding
metadata are synced before one atomic directory rename commits the transfer;
the parent directory is then synced.

Custody files must be private regular files. Symlinks, permissive modes, size
changes, file-identity changes while opening, conflicting evidence, and changed
artifact bytes fail closed. An exact retry verifies the committed artifacts and
evidence instead of replacing them. Signed readiness is stored by an atomic,
synced replacement and a live exact readiness record is reused on retry.
Invalidly signed or transfer-conflicting stored readiness is not treated as an
expired record and cannot be silently repaired. A backward clock step before
the durable readiness instant also fails closed.

The artifact directory is operational custody, not a new semantic authority.
The signed Facets and deployment evidence plus reproduced PostgreSQL state
remain authoritative.

## Blob transfer and the database/filesystem gap

`WalkDeviceSyncMigrationBlobInventory` uses two passes. The first authenticates
the complete transfer digest and validates the body checksum, scope, canonical
ordering, and every entry. Only the second pass invokes a visitor, so no copy
side effect occurs from a prefix-valid or checksum-invalid inventory.

The target coordinator copies blobs before database import. This avoids
installing a standby that is already known to lack content after an ordinary
transfer failure. `BlobContentStore.Put` verifies the signed byte count and the
SHA-256-derived blob ID, including an already-present destination.

There is no atomic transaction spanning PostgreSQL and a filesystem or object
store. Orphan maintenance could remove a pre-import blob before the database
rows commit. The coordinator therefore repeats the complete, authenticated,
idempotent copy after import. Once those database rows exist, normal blob
maintenance recognizes the content as authorized. Readiness is signed only
after the post-import report exactly matches the first report and an independent
target-side open/stream/SHA-256 pass reproduces every signed blob ID and byte
count. This final pass does not rely only on a storage adapter's write
acknowledgement.

## Network and privacy boundary

The blob source is an explicit `BlobContentStore` selected by the caller. It may
later be backed by an authenticated Tor, LAN-direct, or consented public-bulk
client. The coordinator performs no route selection, public listener setup,
credential discovery, or fallback. In particular, it cannot silently replace a
Tor transfer with direct HTTPS.

The transferred blobs remain the existing opaque encrypted relay content. This
checkpoint does not decrypt FEF content or change content-key authority.
Snapshots containing onion-service, TLS-identity, route-configuration, or any
other additional signed artifact are rejected rather than silently ignored.
Those custody kinds require their own complete transfer and verification gate.

## Failure and retry

- Artifact staging is all-or-nothing at the directory boundary.
- Blob copies are content-addressed and idempotent.
- A failure before import leaves at most authenticated orphan blob files, which
  existing maintenance may collect.
- A failure after import leaves a non-writable standby. Repeating the exact
  operation resumes blob verification and uses the PostgreSQL import's exact
  retry behavior.
- A live stored readiness record is returned byte-for-byte. After expiry, a new
  readiness may be signed only while the authenticated snapshot remains live.
- Changed artifacts, signed evidence, signer identity, or import identity fail
  rather than borrowing earlier work.

## Claim boundary and remaining work

This checkpoint supports the headless claim that a prepared Device Sync target
can durably hold exact migration artifacts, copy every inventoried encrypted
blob, import/reproduce logical state, and sign readiness only after target
custody is complete.

It does not provide:

- source-side production artifact materialization and restart coordination;
- authenticated network transfer routes or resumable artifact transport;
- Facets-authorized activation, source retirement, rollback, or cancellation
  cleanup;
- onion-service-state custody transfer;
- startup reconciliation for partially prepared target custody;
- operator commands, HTTP routes, product UI, container cutover, or deployed
  host evidence; or
- Shared Spaces or Compute Pool state migration.

Those remain separate checkpoints. No product-level Move Server or completed
migration claim is made.

## Acceptance evidence

Focused tests cover exact artifact custody, signed descriptor binding,
content-addressed blob transfer, post-import repair of a deliberately removed
blob, exact readiness reuse, tampered artifact rejection before import, tampered
durable readiness rejection, and the no-visitor-before-authentication rule.
Repository-wide Go, race, vet, executable, PostgreSQL, and deployment evidence
are recorded separately at the commit checkpoint.
