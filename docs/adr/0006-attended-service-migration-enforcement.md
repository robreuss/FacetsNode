# ADR 0006: Attended service migration enforcement

- **Status:** Accepted contract and persistence baseline
- **Date:** 2026-08-25
- **Scope:** Device Sync, Shared Spaces, and Compute Pool deployments

## Decision

FacetsNode mirrors the portable attended-migration contracts owned by Facets:
target offers, preparation, migration authority, artifact descriptors, bounded
custody envelopes, snapshots, readiness, activation evidence, rollback
evidence, and the authority-manifest transition state machine.

FacetsNode does not choose or sign Facets authority successors. A deployment
may install preparation only after independently validating the exact target
offer selected by the Facets-authority-signed manifest. Activation and rollback
use evidence-specific registry methods; a bare signed activation or rollback
manifest is rejected by every generic activation/successor path.

Each deployment persists the exact signed authority manifest that produced its
current public binding. During migration, the local binding may name a remote
active deployment only while the signed manifest still names the local host as
the source, target, or prepared deployment. This lets a prepared target remain
non-serving and an old source fail closed after cutover without inventing a
second authority source.

## Fence and signing order

The exporting service state store must atomically commit the snapshot's fence
identifier and state commitment before calling the authority registry. The
registry then enforces this order:

1. `StageMigrationWriteFence` validates and durably stores the exact canonical
   unsigned snapshot payload. HTTP reads may continue, but all state-changing
   capability requests fail closed immediately.
2. `SignStagedMigrationSnapshot` signs only that already-persisted payload with
   the local deployment key. It cannot sign an arbitrary or unstaged snapshot.
3. `ConfirmMigrationWriteFenceSnapshot` permits externally produced evidence
   only when its signed payload exactly equals the staged payload.
4. Activation on the source requires that exact confirmed forward fence.
   Rollback on the target requires the exact confirmed reverse fence.
5. The former source clears its forward fence only while atomically installing
   the fully validated rollback successor that makes it active again.

The HTTP boundary blocks requests arriving after the staged fence; it is not a
substitute for draining or rejecting a request already inside a service-store
transaction. Each Device Sync, Shared Spaces, and Compute Pool write path must
enforce the same fence in its own transaction before runtime cutover can be
claimed. That service-store integration is intentionally deferred here.

Binding-file updates use an owner-only, fsynced temporary file, atomic rename,
and directory fsync. The binding also retains a domain-separated digest of the
exact preparation, activation, or rollback evidence, so a retry remains
idempotent after short-lived evidence expires while changed evidence cannot
borrow an already accepted manifest. Conflicting retries fail.
Reload independently revalidates manifest signatures, canonical payloads,
snapshot signatures, digests, deployment relationships, and fence facts.

## Custody and content boundary

The migration custody envelope is limited to 64 KiB and only permits onion
service state, TLS identity, or route configuration. Go independently opens
the Swift fixture using P-256 ECDH, HKDF-SHA256, AES-256-GCM, and canonical
metadata as authenticated data. Service databases, blobs, and inventories are
never placed in this envelope; their opaque transfer artifacts remain digest
referenced.

## Verification boundary

This checkpoint proves canonical Swift/Go parity and durable public
authority/fence behavior in headless tests. It does not implement public
migration routes, database/blob transfer orchestration, service-specific state
commitments, onion-state handoff, attended UI, container cutover, or rollback
on deployed hosts. Those remain required before any runtime migration claim.

No legacy transition or binding migration layer is provided; Facets is
unreleased.
