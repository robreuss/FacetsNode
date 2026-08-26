# ADR 0014: Device Sync durable migration rollback

- **Status:** Accepted
- **Scope:** Attended server migration during its bounded rollback window
- **Supersedes:** The rollback deferrals in ADRs 0008 through 0013

## Decision

Device Sync rollback is a reverse server migration, not an undo of participant
content. The active replacement deployment first produces an exact
target-to-source snapshot under the still-current activation authority and
atomically fences new writes. The retired source imports that snapshot, copies
and independently verifies every content-addressed ciphertext blob, and remains
non-writable in `rollback_standby`. Only then may it sign readiness.

Facets authority signs the rollback successor from the complete activation,
target snapshot, and source readiness prerequisites. Each deployment applies
that complete evidence through its dedicated BindingRegistry and PostgreSQL
rollback gates:

- the former source becomes writable and clears its old forward fence;
- the replacement target becomes retired and retains its exact reverse fence;
- neither side accepts a bare rollback Manifest;
- the signed rollback deadline is strict and cannot be extended locally.

If no rollback successor is authorized before the deadline, retirement may
discard a prepared `rollback_standby` marker and keep the former source retired.
Returning later is a new attended migration in the opposite direction.

## Exact state replacement

The retired source may contain state that predates writes accepted by the
replacement. Its semantic Device Sync rows are therefore replaced from the
authenticated reverse artifact in one serializable transaction. Permanent root
identities are updated in place; all other included semantic rows are deleted
and reinserted. The transaction re-exports the result and requires identical
state and inventory digests, byte counts, and the domain-separated commitment.

Deployment authority, migration evidence, and local custody records remain
outside the semantic artifact. The database records immutable reverse-import
evidence and binds `rollback_standby` to that exact activation, snapshot,
deployment direction, initial authority, and migration ID.

Deferred write-protection triggers permit semantic replacement only in the
database-authored transaction that created the named reverse-import evidence.
Later transactions cannot use `rollback_standby` as a mutation bypass.

## Crash recovery

Before either local authority store advances, FacetsNode persists a
deployment-signed acceptance journal beside the exact protected reverse
artifacts. Registry advancement and PostgreSQL advancement are independently
idempotent. Startup recovery validates the evidence, artifact custody, local
deployment key, and acceptance instant before completing an interrupted
cutover. An exact caller retry may reuse the accepted journal after operational
evidence expires; new late acceptance remains prohibited.

## User meaning

During an attended Move Server flow, rollback means “move the service back to
the old server using all writes received by the new server.” It does not delete
messages or reverse Shared Space participation. While reverse transfer is in
progress, the new server is write-fenced and the old server is not yet
writable. The UI and public operator/API surface for initiating and reporting
this workflow remain a later checkpoint.

## Verification boundary

This checkpoint provides portable signature validation, database/custody
primitives, headless coordinators, restart recovery, and focused tests. It does
not claim a deployed two-server rollback, production operator route, Facets UI,
or physical-client acceptance.
