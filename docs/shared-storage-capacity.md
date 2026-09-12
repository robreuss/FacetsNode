# Shared storage capacity

The provider, transactional upload guards, default self-hosted policy and
production startup wiring are implemented. Native low-storage acceptance is
still pending; focused tests are not a claim of full Meta transfer acceptance.

Default self-hosted entitlements use shared capacity (all-zero allocation
fields). After tenant authorization, client-supplied per-Space defaults are
normalized to that policy. Positive explicitly issued hosted entitlements remain
bounded; mixed zero/positive policies and hosted unlimited entitlements are
rejected. Fresh schema only: no conversion of an existing acceptance deployment.

A capacity pool comprises one relay PostgreSQL database and the backing blob
filesystem. All service instances for that pool share that database and blob
root. Separate databases must not independently allocate the same pool. The
Box deployment must put database growth and blobs on the same backing pool,
or provide capacity accounting for each backing filesystem before splitting
them. This change does not introduce an external-storage setup interface.

Active upload rows are the durable reservation ledger. Each reserves remaining
staging bytes, a complete temporary publication copy, 64 KiB of metadata
headroom, and 8 KiB per committed chunk. Committed staging already reduces
physical free space, so it is subtracted once from the outstanding promise.
Every allocation/write transaction takes the same PostgreSQL advisory lock
after its existing scoped authority locks. The lock is held through its file
write and metadata commit. Finalization and expiry release the reservation by
changing the upload's durable state. Permanent subscription/device revocation
also releases its abandoned uploads in the same authorized transaction and
queues their staged files for bounded cleanup. Clock expiry alone does not
release reservations. Cancelling a transport task does not revoke custody;
its exact upload remains resumable until explicit revocation or expiry.

The physical reserve is max(2 GiB, ceil(10% of filesystem size)). Capacity
unknown/overflow fails closed for writes. File writes recheck capacity at
boundaries no larger than 1 MiB; failed appends restore the committed prefix,
and failed publication removes the temporary copy while retaining its source.
Existing reads, exact receipt lookup and cleanup do not need a capacity probe.
External filesystem consumers can consume headroom after reservation; in that
case progress remains paused until capacity is restored.

Message publication, domain/member/subscription admission, acknowledgement,
checkpoint staging and activation include metadata headroom. Checkpoint
activation includes temporary retention/deletion rows. The internal direct
prepare/commit blob helpers reject new shared-capacity blobs: production HTTP
upload must go through the durably reserved resumable path. Exact receipts,
revocation and collection remain available under pressure.

Storage pressure returns HTTP 507 with `storage_pressure` and a 30-second
Retry-After, displayed as “Sync paused: the Box needs more storage.” Unknown
capacity has the distinct `storage_capacity_unavailable` code. Neither response
contains paths or underlying filesystem diagnostics. The client keeps its
outbox and automatically retries with a minimum 30-second pause; wake hints do
not bypass that pause.

Verified September 12:

- Physical-boundary tests reject pressure/unknown capacity, stop before the
  next bounded write, preserve short-write errors and permit recovery.
- Real file-store tests preserve the committed prefix and complete staged
  upload after pressure during append/publication, with matching read-back.
- A dedicated disposable PostgreSQL database on the acceptance host passed
  the race-enabled reservation test: 20 simultaneous attempts from two
  accounts and independent store instances admit exactly two reservations
  when capacity fits two, retain them across reopening, avoid double charging
  exact retries, roll back failed writes, and release on finalization/expiry.
- The full PostgreSQL package passes with the race detector against the
  dedicated disposable database: 58 top-level tests, including revocation,
  scope authority, checkpoint pressure/exact retry and store reopening.
  Self-hosted provisioning admits five 256-MiB reservations in one Space despite
  a client requesting the former 1-GiB/one-blob defaults. This is reservation
  admission, not a 1.25-GiB transferred-data claim.
- `go test ./...` passes. Swift transport/scheduler suites pass 47 tests with
  one opt-in live test skipped; the actual automatic pressure timer is tested.

Remaining: fresh isolated deployment and native low-storage pause/recovery
acceptance; remeasure the fixed workload with production capacity checks enabled.
No existing deployment was reset for these tests.
