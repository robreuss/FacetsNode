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

The permanent Device Sync principal references its control relay domain with a
deferred non-cascading constraint. Exact replacement may therefore delete and
reinsert the authenticated control-domain row in one transaction without ever
deleting the principal. A standalone domain deletion still fails unless the
same transaction installs the authenticated replacement before commit.
This is intentionally different from ordinary dependent relay rows, which may
cascade away while the authenticated replacement is materialized.

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

## Adversarial review

The review found and corrected one high-severity implementation defect: the
control-domain foreign key previously cascaded a domain replacement into the
permanent Device Sync principal, causing every nontrivial reverse import to
fail. The live PostgreSQL gate now proves exact replacement without weakening
permanent-principal protection. Injected failures separately prove restart
repair on both the reactivated source and retired target sides of the
BindingRegistry/database cutover. No critical or high-severity finding remains
inside this headless rollback boundary.

One medium operational deferral remains for the attended workflow: a fresh
reverse export commits the PostgreSQL write fence before the registry fence.
The coordinator supports an exact live retry, and every write remains blocked,
but production startup does not yet autonomously resume that pre-terminal
source-preparation stage. The attended operator backend must persist its
operation identifiers and retry it before service readiness. Deployed
two-host transfer, public status/cancellation behavior, custody fault injection,
and client observation also remain outside this checkpoint.

## Verification boundary

This checkpoint provides portable signature validation, database/custody
primitives, headless coordinators, restart recovery, focused tests, and a live
PostgreSQL 17 reverse-import/rollback gate over representative Device Sync
state. The live gate proves divergent state replacement, tamper rejection,
non-writable standby behavior, exact expired retry, restored writes, immutable
import evidence, and permanent-principal/control-domain preservation. It does
not claim a deployed two-server rollback, production operator route, Facets UI,
or physical-client acceptance.
