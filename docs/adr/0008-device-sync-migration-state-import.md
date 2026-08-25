# ADR 0008: Headless Device Sync Prepared-State Import

- **Status:** Accepted for the headless logical-state checkpoint
- **Date:** 2026-08-25
- **Scope:** Device Sync attended-migration state export and prepared-target import

## Decision

FacetsNode has one canonical, headless path for exporting the logical state of
one Device Sync principal and importing it into an authority-prepared target.
The source produces a deterministic service-state artifact, a separate durable
blob inventory, and their domain-separated state commitment while it installs
the migration write fence. The target accepts only those exact staged bytes,
materializes them itself, independently re-exports the resulting state, and
atomically installs immutable import evidence plus a non-writable standby only
when the reproduced bytes and commitment match the source-signed snapshot.

This is a logical-state checkpoint, not a physical PostgreSQL backup and not a
production migration coordinator. Blob content transfer, catch-up, activation,
retirement, rollback orchestration, and user-facing Move Server behavior remain
outside this decision.

## Authority and transfer validation

`MigrationPreparation.ReferenceDigest` identifies the exact canonical
preparation evidence. `MigrationSnapshot.ValidatePreparedTransfer` authenticates
the complete preparation against a Facets trust anchor at an explicit time and
returns defensive projections of the migration, manifests, snapshot, and target
offer. It preserves the existing manifest-chain, signature, deployment
direction, artifact, and validity-window checks.

The target accepts only a Device Sync snapshot whose importing deployment is
the local deployment and whose scope ID is the principal and same-ID relay
tenant being created. The preparation still names the source deployment as
active. The imported target is therefore `standby` and cannot authorize
capability requests until a later Facets-authority-signed activation is
independently validated.

Every request is bound to the signed service-state and blob-inventory artifact
descriptors, including exact byte counts and SHA-256 transfer digests. Both
artifact descriptors are mandatory. Their digests are combined, in fixed
order, under the versioned Device Sync state-commitment domain. A correctly
signed snapshot does not excuse missing artifacts, byte-count disagreement,
transfer-digest disagreement, or a commitment that does not bind the two
descriptors.

## Source export and write fence

`MaterializeAndFenceDeviceSyncMigrationExport` owns a repeatable-read
transaction. Its callback may call `ExportDeviceSyncMigrationState` through the
same transaction, so state extraction and the durable source fence describe one
database snapshot. No production coordinator or artifact-custody layer is
introduced here; a later coordinator must stage the returned streams before it
allows deployment signing.

Export fails closed when the scope has any active partial blob upload or any
nonzero tenant/domain reservation counter. Those states are not silently
omitted or rewritten. Finalized resumable-upload records remain part of the
logical artifact. In-flight work must finish or be abandoned before a source
can produce migration state.

## Canonical artifacts

The service-state codec is a versioned allowlist for exactly one Device Sync
principal and its same-ID relay tenant. It fixes table order, column order,
logical key order, multiplicity, scalar tags, integer and UUID encoding, and
stream framing. Each table section carries its schema and row count. A body
checksum covers the logical body, and the transfer digest covers the complete
stream including the checksum. The blob-inventory stream has a distinct magic
and schema.

JSON columns are decoded and re-encoded deterministically by the Go codec before
storage in an artifact. This normalizes object key order and insignificant
whitespace for the currently stored payloads. It is not a cross-language or
semantic JSON canonicalization claim: representations such as `1` and `1.0`
may remain distinguishable. A future portable format that requires semantic
numeric equivalence needs a separately specified canonical JSON profile and
locked cross-language fixtures.

The included Device Sync tables are:

- `device_sync_account_admissions`, limited to the admission claimed by the
  principal;
- `device_sync_principals`, `device_sync_devices`, and
  `device_sync_device_admissions`;
- `device_sync_spaces`, `device_sync_space_devices`, and
  `device_sync_space_device_admissions`;
- `device_sync_device_revocations`; and
- `device_sync_join_requests`, limited to requests associated with the
  principal.

The included relay tables are:

- `relay_tenants`, `relay_domains`, `relay_subscriptions`,
  `relay_subscription_status_changes`, `relay_members`, and
  `relay_member_admissions`;
- `relay_messages`, `relay_acknowledgments`, `relay_blobs`,
  `relay_credential_rotations`, `relay_tenant_credential_rotations`, and
  `relay_audit_events`;
- `relay_checkpoints`, `relay_checkpoint_fences`,
  `relay_checkpoint_retained_messages`, `relay_checkpoint_retained_blobs`,
  `relay_checkpoint_required_subscriptions`,
  `relay_checkpoint_deletion_messages`, `relay_checkpoint_deletion_blobs`,
  `relay_checkpoint_collections`, `relay_collected_blob_deletions`, and
  `relay_checkpoint_fence_message_tombstones`;
- terminal records from `relay_blob_uploads`, `relay_blob_upload_chunks`,
  `relay_blob_upload_finalizations`, and `relay_blob_upload_deletions`; and
- `relay_tenant_membership_revocations`,
  `relay_tenant_membership_revocation_items`,
  `relay_member_capability_changes`,
  `relay_subscription_rebootstrap_requests`, and
  `relay_subscription_rebootstrap_completions`.

Database-generated `relay_audit_events.event_sequence` is not portable state.
Export replaces it with a zero-based `source_event_ordinal` ordered by the
source sequence. Import assigns fresh target sequences; re-export reconstructs
the same relative ordinal and therefore the same artifact bytes. This assumes
physical audit sequence values are deployment-local and never externally
persisted cursors. If they become protocol identities, migration must add an
explicit cursor reset or mapping contract.

Every omitted stored timestamp or generated column is named explicitly in the
schema allowlist. Live schema drift in a table's columns or types fails export
instead of silently changing migration scope. The current schema gate does not
independently prove every primary-key or identity constraint; the logical key
definitions and live round-trip tests are the accepted checkpoint boundary.

Explicitly excluded state is:

- global ephemeral `pairing_routes` and `pairing_messages`;
- unclaimed account admissions and unassociated join requests;
- active partial uploads, uncommitted chunks, and filesystem staging bytes;
- deployment-local `device_sync_scope_enforcement`,
  `device_sync_migration_exports`, and `device_sync_migration_imports`;
- Shared Space, Compute Pool, and other tenants' rows; and
- transaction IDs, generated timestamps, physical sequences, indexes, locks,
  and other database implementation state.

The blob inventory binds every durable `relay_blobs` row referenced by the
logical state. It does not contain or prove custody of the blob bytes.

## Target materialization and reproduction

`ImportPreparedDeviceSyncMigrationStandby` is the only public PostgreSQL import
entry point. It accepts staged artifact readers, not caller-supplied SQL or a
public materializer callback. The store incrementally validates size limits,
checksums, transfer digests, stream structure, scalar limits, row ordering,
principal ownership, multiplicity, and relation constraints before executing
the decoded insert plan through the internal transaction seam.

The import runs in a serializable transaction under a principal-scoped advisory
transaction lock. Each table materialization is protected by a savepoint. The
store then independently calls `ExportDeviceSyncMigrationState` against that
same transaction. Both reproduced artifact digests, both byte counts, and the
domain-separated state commitment must equal the signed source facts. A validly
signed but logically inconsistent service-state/blob-inventory pair therefore
fails after materialization and rolls back every inserted row.

The current decoder bounds individual scalars at 32 MiB and arrays at 4,096
elements, uses incremental truncated reads, and observes context cancellation
during prehashing. It prevents accidental unbounded allocation at this seam;
deployment-wide artifact and database capacity policies remain future
operational work.

## Immutable evidence, standby installation, and retry

`device_sync_migration_imports` records the complete accepted transfer identity:
principal, migration, snapshot, fence, exporter and importer; preparation
revision and manifest digest; preparation and snapshot records and digests;
artifact descriptors and state commitment; capture, expiry, and first-import
times; and the exact historically authenticated revision-1 authority evidence.
The row is SQL-immutable.

Import evidence and `device_sync_scope_enforcement` are committed atomically.
A deferred composite foreign key makes the exceptional prepared-target standby
shape depend on that exact import: local deployment is the authenticated
importer, still-active deployment is the authenticated exporter, and authority
revision, manifest, transition evidence, and initial authority identity agree.
A target standby cannot be manufactured by setting only an import ID.

After commit, an exact retry returns the immutable record even after the
snapshot and target offer expire. It does not parse artifacts again or change
the first-import time. Any changed signed evidence, artifact identity, initial
authority fact, deployment, or digest conflicts. A failed or rolled-back first
attempt leaves no retry record and must pass current validation again.

## Security and claim boundary

This checkpoint supports the narrow headless claim that FacetsNode can:

- produce deterministic logical Device Sync migration artifacts under the
  same database snapshot as a durable source write fence;
- authenticate and size-bind the exact source-signed transfer;
- materialize and independently reproduce the logical target state; and
- atomically retain immutable evidence beside a non-writable prepared target.

It does not support a claim that a user-visible server migration completed or
that a replacement server is ready. It adds no:

- HTTP, operator, UI, or deployment migration coordinator;
- artifact custody, blob-byte copy, resumable network transfer, or filesystem
  installation;
- target catch-up or source delta replay;
- readiness signature or blob-custody proof;
- activation, source retirement, rollback execution, or recovery coordination;
- startup reconciliation for a prepared target; or
- physical-device, Tor/onion, container, or deployed-host evidence.

The adversarial review found no unresolved critical or high-severity issue in
this headless boundary. Deferred hardening includes a locked independent binary
fixture, semantic cross-language JSON canonicalization if ever required,
primary-key/identity metadata checks in the live schema gate, independently
recomputed source counter/capacity invariants, and an explicit audit-cursor
mapping if physical sequence values become externally meaningful.

## Acceptance evidence

Focused tests cover tampered and truncated streams, schema and principal drift,
unsorted and duplicate rows, scalar and collection bounds, cancellation,
different insertion orders, included semantic mutations, explicit exclusions,
active-upload/reservation rejection, and state-commitment domain separation.

Live PostgreSQL tests cover representative nonempty Device Sync and relay state,
including messages, acknowledgements, blobs, checkpoints, finalized upload
history, associated join state, revocation, rebootstrap state, and tied audit
events. They also cover source-fence/export composition, exact target
round-trip, signed-but-inconsistent inventory rollback, immutable evidence,
standby write rejection, exact retry after expiry, and changed-evidence
conflict.

On 2026-08-25, the repository-wide Go suite passed both normally and with the
race detector while the disposable PostgreSQL gate was configured. `go vet`
passed, as did native executable builds and the Windows/amd64 cross-build. The
separate live-server, Swift-provisioning, physical-device, and deployed-host
integration gates were not configured and are not part of this acceptance.
