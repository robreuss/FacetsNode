# Shared storage capacity

Implementation is in progress. The provider and transactional upload guards
are tested, but production startup, self-hosted policy and client pause/retry
wiring are not yet complete. Do not deploy this as the completed policy.

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
changing the upload's durable state. Clock expiry alone does not release it.

The physical reserve is max(2 GiB, ceil(10% of filesystem size)). Capacity
unknown/overflow fails closed for writes. File writes recheck capacity at
boundaries no larger than 1 MiB; failed appends restore the committed prefix,
and failed publication removes the temporary copy while retaining its source.
Existing reads, exact receipt lookup and cleanup do not need a capacity probe.
External filesystem consumers can consume headroom after reservation; in that
case progress remains paused until capacity is restored.

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
- Five live PostgreSQL upload/reservation/expiry tests pass with no skips.
  `go test ./...` also passes; that general run does not imply all opt-in
  database suites were exercised.

Remaining: shared-capacity self-hosted policy instead of arbitrary byte/count
ceilings; all relevant mutation admission; structured storage-pressure HTTP
and client recovery; cancellation/cleanup coverage; full native low-storage
pause/recovery acceptance. No existing deployment was reset for these tests.
