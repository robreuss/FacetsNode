# ADR 0007: Durable Device Sync Scope Enforcement

Status: partial implementation; not a production migration claim

## Decision

Every PostgreSQL-backed Device Sync principal owns exactly one permanent
`device_sync_scope_enforcement` row. The schema requires
`principal_id = tenant_id`, unconditionally rejects deleting either the
enforcement row or its Device Sync principal, and gives the row one of four
states:

- `standby`: the principal is not allowed to mutate service state;
- `writable`: the exact current authority names this local deployment;
- `export_fenced`: a canonical migration export is durably committed and
  writes are rejected;
- `retired`: this deployment remains non-writable after cutover.

An authority-enabled account claim commits the complete authenticated
revision-1 identity in `standby` in the same transaction as the principal:
local deployment, first validation time, signed Manifest record and digest,
revision, and active deployment. The initial deployment, validation time,
Manifest digest, and Manifest bytes remain separately stored and SQL-immutable
across later current-authority updates. The row also records an immutable
full-width PostgreSQL transaction identity bound by a `BEFORE INSERT` trigger;
callers cannot supply or later rewrite it. This prevents an exact provisioning
retry from substituting a different valid revision-1 enrollment after a crash
and limits the standby write exception to the row's actual creation
transaction.

The current authority additionally stores its validation time and any required
transition-evidence digest. PostgreSQL `bigint` bounds every persisted
revision/time value. Loading a row re-verifies canonical signed Manifest bytes,
the reference digest, the exact Device Sync scope ID, and temporal validity at
the recorded acceptance instant.

Migration exports store the exact canonical `MigrationSnapshotPayload` bytes
(at most the service-authority signing limit of 262,144 bytes), ordinary
SHA-256, state commitment, and exact scope/deployment/fence facts. A deferred
foreign key binds the active fence to its export. SQL rejects updates to export
rows and rejects deleting one while its principal exists. Export uniqueness
includes the exporting deployment, so an attended migration can later support
both forward and rollback-direction exports for one migration ID.

This unreleased migration has no compatibility or backfill path. It explicitly
fails if any preexisting Device Sync principal lacks its enforcement row; such
a development database must be reset.

## Repairable initial claim and activation

Production Device Sync configuration requires deployment signing custody,
route policy, and a persistent service-authority BindingRegistry. Production
server construction rejects a Device Sync store that does not implement the
authority-bound claim contract.

The account-claim sequence is:

1. Authenticate the complete `InitialEnrollment` and independently verify its
   active deployment descriptor against the local deployment signer.
2. For an unclaimed admission, require both the Manifest and deployment offer
   to be current at the explicit server time.
3. Commit the exact initial authority and principal in database `standby`.
4. Install the byte-exact binding in BindingRegistry. An exact installed retry
   returns without rewriting the registry; a conflicting binding fails.
5. Flip only that exact committed database row from `standby` to `writable`.

The final state flip does not re-evaluate deployment-offer or Manifest time.
It introduces no authority and therefore remains repairable after an offer has
expired. An exact already-claimed retry may reconstruct the same enrollment at
a later validation time; retry identity deliberately excludes invocation time.
A different signed Manifest is a conflict even when provisioning is identical.
Imported-target activation and source write retirement now have an exact
evidence-bound PostgreSQL primitive described by ADR 0011. Public exposure,
cross-store orchestration, and automatic restart reconciliation still require
the migration coordinator.

Registry identity conflicts return the existing stale/invalid authority 409.
Registry custody/persistence failures and database activation failures return
stable 503 `device_sync_authority_unavailable`; the handler never reports a
successful claim before both registry and database activation finish.

## Mutation and export lock protocol

Bound production HTTP mutations use one common two-level protocol rather than
reimplementing authority checks in every capability store method:

1. Parse and authenticate the exact scope, authority revision, Manifest
   digest, deployment, route, and traffic class from the request.
2. Acquire BindingRegistry's per-scope mutation lease, then reauthorize after
   admission so a migration fence that appeared while waiting cannot be
   missed.
3. Seal those registry facts as a `MutationAuthorization`; callers cannot
   construct or alter that value outside the service-authority package.
4. The authority-bound PostgreSQL store independently compares the sealed
   facts with its immutable local deployment ID and locks the durable
   enforcement row `FOR SHARE` in a lock-only Read Committed transaction.
5. Retain both leases through the complete capability handler, including
   streamed bodies, database commits, and filesystem callbacks, then release
   them idempotently.

The lock-only transaction is not the final atomic write check. Migration 041
attaches a deferred constraint trigger to every current relay or Device Sync
service-data table carrying `tenant_id` or `principal_id`, plus the claimed
principal on account admissions. The enforcement and migration-export tables
are deliberately excluded because their own immutability, state-transition,
and foreign-key triggers govern them. At commit, each service-data trigger
locks the enforcement row `FOR SHARE` and requires `writable`. The only standby
exception compares the row's immutable initial-claim `xid8` with the current
transaction, which permits the atomic initial account claim without allowing a
later update to reopen it. Thus, if PostgreSQL terminates the separate
request-fence session, a migration can establish non-writable state, but a
previously started mutation cannot commit afterward. Shared Spaces rows have
no Device Sync enforcement record and retain their existing behavior. Future
schema migrations that add scoped service-data tables must attach the same
constraint trigger.

The durable guard rejects nil/zero expectations, another local or active
deployment, stale/future authority, authority mismatch, and every non-writable
state. Device Sync requires at least two PostgreSQL connections. Concurrent
guard transactions are limited to half of the configured pool so every
admitted handler retains database capacity for its actual operation.
The long-poll wake endpoint is the deliberate exception to whole-handler lease
retention: it takes and releases a short mutation boundary for the pre-wait
fetch, holds no database permit while idle, and repeats exact authorization and
fencing for the post-wake fetch.

Background blob expiry and orphan deletion use the same order per tenant:
BindingRegistry mutation lease, sealed current Device Sync authority, durable
`FOR SHARE` lease, database mutation or filesystem callback, release. Candidate
discovery is read-only and groups all eligible uploads by tenant before the
successful-mutation bound is applied, so a fixed prefix of fenced tenants
cannot hide a later writable scope. Authority time is sampled freshly after
the process lease is admitted; the earlier maintenance cutoff is used only for
expiry and deletion eligibility. Shared Spaces continues to use the aggregate
content-blind relay maintenance implementation. Expiry remains globally
bounded to 256 successfully expired uploads per pass. A committed prefix is
returned and counted even if a later candidate fails, and fenced or unavailable
tenants are reported without starving later writable tenants in that pass.

Migration export takes the same row `FOR UPDATE`, draining prior shared locks
and excluding new guarded writers. Only after the exclusive lock is held does a
trusted snapshot materializer read service state through the still-open
transaction and return exact canonical snapshot bytes. That transaction then
inserts the immutable export and installs its active fence. Only after commit
may a coordinator sign or publish evidence.

The materializer callback eliminates the unsafe possibility of constructing a
snapshot before acquiring the durable lock. Its narrowed Query/QueryRow
interface is a trusted-code seam, not a database capability sandbox: PostgreSQL
queries can technically contain data-modifying SQL.

`MutationAuthorization` is sealed evidence passed immediately from registry
authorization to the durable store; it is not a bearer credential or a
general reusable in-process capability. The durable store still compares its
scope, deployment, revision, digest, authority time, and current write state.

`devicesync.ErrScopeWriteFenced` is the stable `errors.Is` sentinel for a write
rejected because the durable state is non-writable. A conflicting expectation
on an otherwise writable row is an authority conflict, not a fence error.

## Startup readiness and repair

Before HTTP listeners or background maintenance start, Device Sync compares
every validated durable enforcement row with a defensive, temporally current
BindingRegistry identity snapshot. An expired Manifest therefore fails
readiness even though its historically recorded acceptance remains valid
evidence. Empty database plus empty registry and exact writable pairs are
accepted. The only automatic repair is the exact revision-1 crash window
where registry activation committed but the same database authority remains
standby; the database is flipped to writable and re-read. Missing, extra,
unbound, conflicting, later-standby, fenced, or retired state fails startup.
The registry is never reconstructed from database facts.

## Pairing-expiry boundary

Capability-authenticated pairing mutations pass through the common HTTP
authority guard, but the global pairing tables do not persist a Device Sync
scope. The generic cleanup loop therefore cannot acquire a principal-specific
lease. It only physically purges messages and routes that are already
logically unavailable by expiry or closure. A future migration materializer
must exclude these ephemeral records, and an attended move must not promise to
preserve an in-flight pairing session. Persisting principal association for
pairing and migrating active sessions would be a separate contract change.

## Remaining migration boundary

This checkpoint makes the current production HTTP and blob-maintenance paths
fail closed against durable Device Sync authority, but does not yet make an
attended migration production-ready:

- the snapshot materialization/export method has no HTTP, operator,
  background, or migration-coordinator call site and is not production
  reachable;
- no production snapshot-state/blob materializer or snapshot signer is wired;
- imported-target standby, authenticated copy, target catch-up, activation,
  old-host retirement, rollback-direction export, and recovery coordination
  are not implemented;
- restart readiness deliberately rejects `export_fenced` and `retired` rows
  until the migration coordinator owns their recovery path;
- database triggers make direct internal store writes fail closed once a scope
  is non-writable, but they do not authenticate client revision, Manifest
  digest, route, or traffic class; new production entry points must still use
  the common HTTP or background authority guard;
- active pairing sessions are explicitly outside the migration snapshot as
  described above.

Accordingly, the implemented evidence supports durable current-host write
enforcement and exact initial-activation crash repair. It does not support a
runtime or deployment claim for server migration, rollback, or recovery.
