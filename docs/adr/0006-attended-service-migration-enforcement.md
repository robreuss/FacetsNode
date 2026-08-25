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

Bound capability routes now declare read versus mutation access explicitly;
HTTP verbs are not used as a proxy. A scope-keyed, writer-preferring in-process
gate admits mutations before their handler runs, re-authorizes them after
admission, and retains the lease until `ServeHTTP` returns. An exclusive
migration lease blocks new mutations and drains all mutations already admitted
through that middleware in the same FacetsNode process. This includes relay
GET and HEAD operations, bulk-grant issuance, and Shared Space participant
reads that transitively mutate checkpoint-expiry state, plus handlers that
perform filesystem callbacks.

That in-process drain is not a durable database fence. It does not cover a
second FacetsNode process, a background task, an unbound route, or code that
invokes a store directly. A crash can also separate a service-state commit
from registry-fence persistence. Each Device Sync, Shared Spaces, and Compute
Pool transaction must therefore atomically check/commit a fence in its own
durable state store before runtime cutover can be claimed. That service-store
integration remains intentionally deferred.

Pairing/rendezvous records also have no persisted Facets service scope. Their
route IDs cannot be checked against the scope in the authority headers, so a
caller can present any current binding of the configured service kind. A
scope-keyed lease therefore does not prove that pairing state was drained;
pairing must gain and enforce durable scope ownership or be disabled during
migration before that state can be included in a cutover claim.
Device Sync account-admission creation is likewise pre-principal, while its
claim route is intentionally unbound during initial authority enrollment;
neither operation is part of a per-principal drain proof yet.

Binding-file updates use an owner-only, fsynced temporary file, atomic rename,
and directory fsync. The binding also retains a domain-separated digest of the
exact preparation, activation, or rollback evidence, so a retry remains
idempotent after short-lived evidence expires while changed evidence cannot
borrow an already accepted manifest. Conflicting retries fail.
Reload independently revalidates manifest signatures, canonical payloads,
snapshot signatures, digests, deployment relationships, and fence facts.
On supported Unix systems, a normalized binding path also has one exclusive
process owner for the registry lifetime. A second process fails closed until
the owner calls `Close`; the lock must be a private regular file in an
owner-controlled directory and path/open-file identity is verified. This
prevents divergent in-memory successors from competing to replace the same
file. Persistent authority fails unsupported on Windows until a native
interprocess lock exists.

An accepted preparation remains usable if only its superseded predecessor
manifest later expires. Transfer reconstructs that predecessor at the
historical overlap where the preparation was valid, but still requires the
preparation manifest, target offer, snapshot, readiness, and activation to be
live at cutover.

An exact already-confirmed snapshot retry remains idempotent after its
short-lived evidence expires. A first confirmation at or after expiry still
fails, and any changed payload, signature, or digest conflicts.

## Custody and content boundary

The migration custody envelope is limited to 64 KiB and only permits onion
service state, TLS identity, or route configuration. Go independently opens
the Swift fixture using P-256 ECDH, HKDF-SHA256, AES-256-GCM, and canonical
metadata as authenticated data. Service databases, blobs, and inventories are
never placed in this envelope; their opaque transfer artifacts remain digest
referenced.

## Verification boundary

This checkpoint proves canonical Swift/Go parity, durable public
authority/fence behavior, and same-process bound-HTTP mutation draining in
headless tests. It does not implement public
migration routes, database/blob transfer orchestration, service-specific state
commitments, onion-state handoff, attended UI, container cutover, or rollback
on deployed hosts. Those remain required before any runtime migration claim.

No legacy transition or binding migration layer is provided; Facets is
unreleased.

The cross-repository adversarial review is recorded by Facets at
`docs/security/attended-service-migration-adversarial-review.md`. Remaining
claim limits include the service-store transaction race described above,
client monotonic-history recovery, physical-ingress route attestation, and
native Windows interprocess locking.
