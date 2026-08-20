# Facets transport-envelope contract

Status: frozen v1 development contract. This document governs the shared
transport substrate used by the separately deployable Facets Device Sync and
Facets Shared Spaces services. It does not define canonical Facets content,
membership authority, billing, or compute policy.

## Scope and confidentiality

The server routes durable opaque envelopes. For Device Sync, payloads and blob
bytes are always client-encrypted; the service receives no content key,
plaintext FEF, or semantic graph. Shared Spaces select their own immutable
security profile. Private and Secure Shared Spaces are content-blind E2EE
profiles; the future managed profile has a separately specified
service-readable custody boundary.

An envelope is transport data, not content authority. A bearer admits transport
delivery only. Client-held principal, device, participant, and key authority
decide whether a decrypted payload is accepted.

## Envelope v1

Every v1 envelope has a deterministic message ID, a source identity digest,
payload kind, content type, SHA-256 digest, unpadded base64url payload bytes,
dependency message IDs, and zero or more content-addressed blob references.
The payload digest covers the exact payload bytes. A blob reference identifies
the blob, its SHA-256 digest, byte count, and content type.

The allocated kinds are:

| Kind | Purpose |
| --- | --- |
| `fef_checkpoint` | Bootstrap or compact replica checkpoint. |
| `fef_mutation_batch` | Ordered canonical FEF mutations after a checkpoint. |
| `control_message` | Encrypted client authority or configuration control traffic. |
| `blob_manifest` | References required blob bytes without reconstructing content. |
| `delivery_receipt` | Durable transport or canonical-application result. |
| `correction_receipt` | Typed recovery request, including missing dependencies. |
| `ai_job_request` | Reserved opaque request envelope for future compute routing. |
| `ai_job_result` | Reserved opaque result envelope for future compute routing. |

The AI kinds reserve syntax only. They do not imply a compute broker,
participant entitlement, or worker authorization.

The normative portable fixture is byte-identical in the Go and Swift source
trees:

```
FacetsNode/internal/protocol/testdata/facets-server-transport-portable-v1.json
Facets/Packages/FacetsDeveloperKit/Tests/FacetsNodeClientTests/Fixtures/facets-server-transport-portable-v1.json
```

For this revision its SHA-256 is:

```
1102b3f64c007b9bbf66c9eb74cb87b6b512e84241419df8827f7149b4e3ea26
```

## Secure roster authority fixture

Secure Shared Space roster authority is deliberately separate from a transport
envelope: it is an independently signed, hash-linked client trust record. The
portable fixture fixes its P-256 signature encoding, canonical signing bytes,
initial roster, and one successor transition:

```
FacetsNode/internal/testfixture/shared-space-secure-roster-attestation-portable-v1.json
Facets/Packages/FacetsDeveloperKit/Tests/FacetsFEFTests/Fixtures/shared-space-secure-roster-attestation-portable-v1.json
```

The Swift fixture is a required counterpart before a Secure Shared Space client
is enabled. It must be byte-identical to the Go fixture, whose SHA-256 is:

```
aad269a61cff902b857dea7b64a423ce52a97f57a918bfbe43c8a58945bd1b1a
```

A client verifies an initial attestation against the provisioned host
participant and accepts a later roster only when its signed revision,
predecessor digest, active participant set, and key epoch form a valid
successor. A relay response is never membership authority by itself.

## Delivery and canonical application

Delivery is at least once. A client deduplicates by deterministic message
identity, validates envelope integrity and client authority, decrypts the
payload where applicable, and sends all canonical FEF through the standard
Facets FEF importer. No Device Sync or Shared Spaces transport path writes
directly to the Facets core database.

A receipt may report durable relay acceptance, but a `canonical_applied`
acknowledgement is emitted only after the client has committed the canonical FEF
transaction. Rebuildable lenses, filters, analytics, and other projections are
derived locally after that commit. They are not authoritative transport state.

## Checkpoints, tails, cursors, and blobs

A checkpoint establishes a durable replica baseline. Mutation batches form the
tail after that checkpoint. Cursors and receipts make retransmission,
interrupted delivery, duplicate delivery, and restart recovery idempotent.
Disposable wake hints may reduce perceived latency but reliable cursor polling
remains the delivery guarantee.

Blobs are content-addressed and may be uploaded or resumed separately from the
envelope that references them. Receivers verify digest and size before marking
the associated canonical application complete. A corrected bundle reuses a
known blob reference rather than retransmitting blob bytes unnecessarily.

## Dependency correction

The server never reconstructs a Facets semantic graph. If a receiver lacks an
envelope dependency or a required blob, it emits a typed correction receipt.
The sender responds with a corrected complete bundle containing the required
parent/dependency references and any missing blob manifest. The receiver may
retain canonical records whose relationships are unresolved, but it does not
acknowledge the affected bundle as canonically applied until the dependency
closure is valid.

This is a recovery path, not normal operation. Publishers should send the
smallest complete relationship bundle in dependency order; repeated correction
or unrecoverable dependency failure is observable diagnostic state.

## Compatibility rules

Envelope kinds, fields, receipt/error vocabulary, digest rules, and fixture
bytes are versioned protocol surface. A breaking change increments the version,
adds cross-language golden fixtures and decoder tests, and does not rely on
legacy migration for unreleased development state.
