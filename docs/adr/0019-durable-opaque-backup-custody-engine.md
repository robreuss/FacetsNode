# ADR 0019: Durable opaque Backup custody engine

## Status

Accepted as a non-runnable durable-engine checkpoint. It implements the local
custody coordinator, protected filesystem storage, and a dedicated PostgreSQL
store behind Go interfaces. It does not add an HTTP route, server-app assembly,
deployment configuration, retention scheduler, deletion, or garbage collection.

## Decision

Facets Box Backup custody is a content-blind service. It stores only the signed
service-authority records needed to authorize custody, random account/target/
Backup-set coordinates, canonical operation records, opaque encrypted `.b20`
bytes, and signed custody or retention receipts. It does not parse FEF payloads,
decrypt Backup content, learn Space identity, or decide whether an export is
complete, safe, current, or restorable.

The engine has its own PostgreSQL schema and its own private content root. It is
not backed by Device Sync, Shared Spaces, relay, or Sentry tables. The content
root, staging directory, object directories, prepared-account journal, and
process locks are owner-private and are revalidated by stable filesystem
identity. Symlinks, replacement roots, unexpected modes, and ambiguous files
fail closed. A process lock serializes staging and publication across server
processes sharing one root.

Account provisioning is ordered as follows: persist an exact redacted prepared
claim, commit a standby account with the complete canonical initial enrollment,
activate the exact service binding, then mark the account writable. The prepared
journal is the only cross-store repair source. It uses deterministic
account-scoped staging, exclusive immutable publication, file and directory
`fsync`, and byte-identical retry. It never stores an admission bearer. A lost
response after successful journal cleanup is repaired from the exact committed
database claim; a standby claim can reconstruct the same journal entry. Fresh
admission expiry applies before first preparation, while exact committed replay
does not rewrite its original acceptance time.

Every new mutation is serialized in this order: acquire the Binding Registry's
account mutation lease, sample server time, freshly authorize the exact current
authority, then hold the PostgreSQL account/target/upload row lock and authority
fence through the filesystem effect and synchronous database commit. Stored
authority revision, manifest digest, deployment, and a durable server-time
high-water mark must agree. Reads also use a coherent durable authority/high-
water snapshot before opening the exact held object. Registry authorization and
database authority are both required; neither substitutes for the other.

Uploads reserve one immutable request identity and stable upload identity before
creating staging. Each append holds the upload row lock across tail
reconciliation, write, file `fsync`, and committed-offset update. Exact lost-
response replay must match offset, length, digest, next offset, and the bytes in
the held staging/object inode. The durable chunk ledger is a bounded contiguous
chain: first offset zero, every offset equals its predecessor's next offset, and
the final next offset equals committed bytes. Chunk count, chunk size, active
uploads, staging bytes, targets, generations, request rows, retained receipts,
and committed bytes have positive per-account limits. This checkpoint has no
garbage collection, so those limits are permanent safety bounds rather than a
rotation policy.

Finalization streams the `.b20` outer grammar through a fixed-memory validator,
with configured signed-64-bit size caps. It hashes the exact received bytes and
requires canonical header fields, contiguous recovery sections, one catalog,
one-or-more recovery sections, one finalization section, and exact EOF. The
target head and the encrypted outer predecessor are a dual compare-and-swap.
Generation values above signed PostgreSQL range fail before reservation or
publication.

Immutable publication exclusively links the staged inode at an exact derived
object path, verifies its size and digest, makes it read-only, syncs the object
directory, removes the writable staging alias only when it is the same inode,
then syncs the staging and ancestor directories. Every durability step repeats
on retry. If a crash occurs after object publication but before the database
commit, the exact orphan object is the only accepted repair source; it is never
reopened for append. The post-publication receipt/head commit uses a bounded
context derived from `context.WithoutCancel`, so client cancellation cannot
turn a durable object into an abandoned partial authority result.

Custody and retention receipts are signed only after the deployment signer is
authorized by the exact historical trust anchor and manifest. Every loaded or
replayed receipt is revalidated against that same historical authority. A
retention receipt also revalidates and exactly links its custody receipt,
generation, and requested minimum retention time. Retention is a point-in-time
proof that the exact immutable bytes are present; it is not a promise of future
retention. No object deletion or receipt revocation is implemented here.

Request IDs are global within the dedicated store. Exact byte-identical retries
return the prior durable result; conflicting reuse across operations, accounts,
targets, credentials, or content fails closed. Target creation uses a
client-supplied random credential reference and bearer so a lost response can be
retried without persisting the raw bearer. Bearers are explicitly projected only
for future transport use and are mechanically redacted from formatting and JSON.

## Crash and threat boundary

The engine is designed to fail closed under process crashes between reservation,
append, publication, and database commit; concurrent processes; stale authority;
clock rollback relative to the durable high-water mark; request replay; file or
directory substitution; object tampering; malformed/oversized streams; quota
exhaustion; and a deployment signer that is not authorized by the exact accepted
authority history.

It does not claim protection against an operating-system or database
administrator who can coherently rewrite both PostgreSQL and the content root,
availability after physical loss of the Box, future retention without a newer
proof, semantic correctness of encrypted content, or possession of the user's
recovery key. Replication, off-site durability, monitoring, billing, and
rollback-resistant external witnessing are later concerns.

## Exclusions

This checkpoint adds no network listener or HTTP handler; no runnable Backup
service; no client scheduling, capture, encryption, or restore behavior; no
decryption key custody; no FEF semantic validation; no deletion, pruning,
rotation, deduplication, or household/Shared-Space coordination; no Node
transport observation; and no Sentry finding or automatic response. ADR 0018
continues to describe the portable contract checkpoint; this ADR describes the
subsequent local durable engine only.
