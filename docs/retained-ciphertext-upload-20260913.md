# Retained ciphertext upload correctness

September 13, 2026. Native Proxmox participant-sponsorship acceptance exposed
`409 blob_upload_collision` when a subsequent checkpoint reused exact ciphertext
from the existing client seal-once vault. The earlier upload had finalized and
its client outbox record had correctly completed. The new checkpoint persisted
new upload/retry identifiers, which the server confused with a content collision.

Both memory and PostgreSQL creation paths now allow a fresh attempt addressing
the same domain-bound ciphertext and length. Ordinary authorization, active
subscription, fence, retry identity, staging, capacity reservation, and chunk
validation remain required. Finalization already serializes against collection
and retains the existing physical blob without double-counting finalized bytes.
This correctness repair still transfers/stages the ciphertext again. It does
not implement cross-service reuse or skip-transfer custody proofs.

Verification:

- Full local `go test -race ./...` passed; database-dependent tests in that run
  were not live database evidence.
- Explicit `-race -count=1 -v` relay, HTTP, and PostgreSQL suites passed against
  disposable PostgreSQL 17.6 on Proxmox, with no skipped tests. Tests cover a
  second upload after finalization, preserved reservations, pool restart,
  exact create/finalize retries, changed-length rejection, and one physical
  publication with no leaked or duplicate reservation accounting.
- With only the production fix reversed, the same test packet fails in memory
  and PostgreSQL with the native `blob_upload_collision` error. Restoring it
  passes again.

Evidence on the coordinator: `/tmp/facets-retained-ciphertext-node-tests.log`,
`/tmp/facets-retained-ciphertext-postgres-regression-before.log`, and
`/tmp/facets-retained-ciphertext-postgres-after.log`.

Native retry completion and full semantic parity remain separate pending gates.
