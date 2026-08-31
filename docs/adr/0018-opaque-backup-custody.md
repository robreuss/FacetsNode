# ADR 0018: Opaque Backup custody

## Status

Accepted as a contract-only checkpoint. No HTTP route, database, object store,
client intake, or retention worker is introduced here.

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
References in the portable request are not bearers; a future handler must
authenticate the corresponding credential before it evaluates the contract.

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

The same protocol applies to local Facets Box and hosted Facets Box. Service
transport, quotas, HTTP paths, database/object-store transactions, credential
issuance, and account billing are later checkpoints. Node transport observations
explicitly reject this scope; Backup receipts are not Sentry evidence or a Node
observation stream.
