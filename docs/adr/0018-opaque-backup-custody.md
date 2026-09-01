# ADR 0018: Opaque Backup custody

## Status

Accepted and implemented as a runnable custody-service vertical slice plus the
bounded generation-discovery and range-transport checkpoint. App orchestration,
automatic scheduling, retention-policy rotation, and deletion remain separate.

## Decision

Backup custody is an account-scoped `backup_custody` Facets service. Each owned
Space maps locally to one random Backup-set and one independently random custody
target. Neither identifier contains or reveals a Space ID, title, participant,
recipient, recovery profile, or plaintext metadata. Multiple devices belonging
to the same account may later receive distinct target credentials for the same
target and Backup set. Household and Shared-Space deduplication are excluded.

Account admission and target operation authorization are different types and
are never interchangeable. A target credential is bound to one account,
target, Backup set, capability set, credential identity, nonce, and expiry.
References in the portable request are not bearers. The handler authenticates
the corresponding current credential and exact accepted account-control ledger
before it evaluates any target operation.

For publish, the service parses the encrypted Backup outer record and computes
its SHA-256 digest and byte count itself. It never trusts client-sent digest or
length. The in-memory `ComputeGenerationRecord` helper is contract/test
convenience only: the production service must stage to an owned file and perform
bounded, O(1)-memory framing validation and hashing because the outer protocol
has no aggregate-size cap. The generation record binds target, Backup set,
generation, upload identity, exact predecessor reference, digest, and byte count. Generation
one is accepted only for an uninitialized target. Every successor is an atomic
compare-and-swap against the exact current head. Object bytes and the new head
must be durable before a custody receipt is signed. A stable request identity is
idempotent only for byte-identical facts; conflicting replay or a concurrent
loser fails and returns the current head. A target cannot be rebound to another
Backup set through a normal write.

Generation, custody receipt, and retention receipt references use distinct
domains; custody and retention also use distinct canonical low-S ES256
signature domains.
Receipt authorization requires the exact historical authority manifest and
active deployment at the receipt time. Retention refers to a verified custody
receipt and attests only that the exact opaque bytes are present at the
server-issued receipt time. A request carries a descriptive client time and a
minimum-retained-through threshold; the service may issue a proof only when its
own verified time has reached that threshold, and the signed
`retainedThroughMilliseconds` is exactly the server `issuedAtMilliseconds`.
A later point requires a new proof after rechecking the object. Retention does
not claim that the FEF is complete, clean, latest-known-good, decryptable, or
restorable.

Generation discovery is bounded to 32 items per canonical page. The first page
pins one exact signed custody head. Every successor request exact-binds both
that head and the prior page's final generation reference; the service reads
only the resulting immutable prefix even when a concurrent publish advances
the current target. Every item carries its original deployment-signed custody
receipt. A client must authorize each receipt against its exact accepted
historical service manifest; the page wrapper itself is not authority.

Reads require an exact generation reference, positive offset, and a bounded
byte count no greater than 64 MiB. A partial response carries the complete
object byte count and digest, exact generation reference, original custody
receipt, and exact returned range coordinates. The content store authenticates
the complete object before opening the range, retains the exact regular-file
descriptor and inode through streaming, and detects pathname, type, or size
substitution. Full-file digest verification and Backup b20 authentication still
belong to the client after assembling the ranges; no partial range is a restore
or plaintext-validation receipt.

Large upload chunks and download ranges additionally require a short-lived
deployment-signed bulk grant. Backup issues a grant only after current target
credential validation against its durable ledger. Its resource ID
domain-separates upload chunks from download ranges and binds the exact public
credential-reference digest plus upload or generation identity, offset, and
byte count. The generic signed grant separately binds Backup scope, exact
authority manifest, deployment, route, direction, maximum bytes, and a maximum
five-minute validity interval. Swapping any credential, route, direction,
resource, offset, or count fails before storage effects. Grants never convey
decryption, retention-policy, deletion, or restore-selection authority.

The same service binary and protocol apply to local and hosted Facets Box.
The dedicated PostgreSQL database and private opaque content root are not relay
or application stores. Public errors deliberately do not distinguish wrong
credentials from absent/conflicting target objects. Begin-upload exact replay
remains the only upload status/resume operation. No app client, UI, scheduler,
Recovery Root custody, Personal Sync delivery, account billing, retention
worker, deletion, or opaque-object interpretation is added by this transport
checkpoint. Node transport observations explicitly reject this scope; Backup
receipts are not Sentry evidence or a Node observation stream.
