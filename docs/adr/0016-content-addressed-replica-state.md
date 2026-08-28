# ADR 0016: Content-addressed replica state roots

Status: Accepted for implementation, 2026-08-27

## Context

The first checkpoint implementation captures the complete canonical Facets
population into newly signed messages and newly encrypted relay blobs on every
checkpoint. It is correct as a content-blind bootstrap, but unchanged content
is encoded, encrypted, uploaded, and retained again. That cost becomes
unacceptable for large Spaces, replacement-device recovery, household Edge
staging, and Shared Space onboarding.

FacetsNode already has the required opaque storage primitives: independently
resumable content-addressed encrypted blobs, signed encrypted relay messages,
checkpoint roots that retain exact message/blob sets, and latest-plus-previous
checkpoint retention. A second state database or a semantic server-side Space
would duplicate those primitives and weaken the content-blind boundary.

## Decision

A complete recoverable replica state consists of one signed root message,
content-addressed state pieces, and the ordinary message tail after that root.

- A state piece is the exact canonical bytes of one independently importable
  FEF artifact payload. Its client-side `pieceID` is the unpadded base64url
  SHA-256 of those bytes.
- A piece descriptor binds the piece byte count, dependency piece IDs, required
  resource/media blob identities and byte counts, and item count.
- A state root binds the Facets exchange domain, content-key epoch, local core
  revision used to detect a torn capture, causal frontier, predecessor message
  set, canonical piece graph, predecessor-root digest, and capture time.
- The root is accepted only as the payload of an authorized, signed replica
  checkpoint message. Piece bytes have no independent import authority.
- The relay-encrypted checkpoint payload maps client-side piece/resource IDs to
  relay-encrypted blob IDs. FacetsNode sees only its normal ciphertext envelope,
  opaque blob IDs, byte counts, checkpoint custody, and retention metadata.
- A publisher persists each sealed encrypted piece and route. An unchanged
  piece reuses those exact ciphertext bytes rather than applying randomized
  encryption again. Equality is therefore visible only within that encrypted
  exchange domain. Different domains or key epochs do not share ciphertext
  identity.
- A successor root names the exact predecessor digest, cannot move its causal
  frontier or key epoch backward, and may reuse any unchanged piece IDs. A key
  epoch change recaptures and reseals the pieces under the new epoch.
- The existing relay checkpoint candidate retains the new root message, all
  encrypted piece blobs reachable from it, and their required encrypted
  resource/media blobs. No new FacetsNode persistence subsystem is introduced.
- The active root and its immediate predecessor remain available. Collection
  may remove messages and blobs unreachable from either root only after the
  existing custody requirements are satisfied.

The canonical portable contract is mirrored in Swift and Go:

```text
Facets/Packages/FacetsDeveloperKit/Tests/FacetsFEFTests/Fixtures/replica-state-root-portable-v1.json
FacetsNode/internal/testfixture/replica-state-root-portable-v1.json
```

Its exact-file SHA-256 is:

```text
c0ad2b2d1ed0f5951686987c0a6d75f837e0ab231c5d649726d943d562b91b72
```

The Go types and fixture tests prove cross-language encoding and digest parity.
They are not called by FacetsNode request handling and do not authorize the
server to decode client state.

Complete-Space coverage has a separate byte-identical inventory fixture:

```text
Facets/Packages/FacetsDeveloperKit/Tests/FacetsFEFTests/Fixtures/replica-complete-space-coverage-portable-v1.json
FacetsNode/internal/testfixture/replica-complete-space-coverage-portable-v1.json
```

Its exact-file SHA-256 is:

```text
9fc93c8500e81a8f9cffc1678ec6718e81231cb4bb621c5dd2d67de2a59f88a0
```

The complete inventory requires canonical objects (including Text, Document,
and Annotation), relationships, extensions, media, and exact content-addressed
sidecars for category definitions and memberships, the active and archived
Document library, extension schemas, Lenses, ordered compositions and snapshot
sets, exact Dataset source files, portable analytics, and Workspace designs. Device-private settings,
credentials, queues, caches, Document undo history, and local Assistant
conversation state are outside the portable semantic Space.

Production capture emits `complete-space.v1` only under exclusive snapshot
admission, binds the durable source revision, and validates every manifest and
canonical-object inventory before publication. Client replacement and the
FacetsNode rebootstrap routes are enabled only for an exact activated
checkpoint/root. The client applies that root into a demonstrably empty staging
package and replaces the fenced package atomically. FacetsNode restores
publication only after the recovering subscription records applied receipts for
every retained envelope in the recovery interval, including envelopes that the
same subscription published before recovery.

## Digest encoding

`referenceDigest` is unpadded base64url SHA-256 over the domain separator
`Facets replica state root v1` plus a NUL byte and the validated fields in wire
order. Integers and collection counts are unsigned 64-bit big-endian values;
strings are an unsigned 64-bit UTF-8 byte count followed by bytes; UUIDs are
their 16 network-order bytes; piece/blob digests are their decoded 32 bytes.
Maps and all repeated identities use their contract-defined lexical order.

## Consequences

- A small semantic change can publish a complete new recovery root while
  uploading only changed pieces.
- Baseline recovery and ordinary mutation delivery no longer require two
  unrelated storage formats. Both ultimately apply canonical FEF through the
  client importer.
- FacetsNode, Facets Edge, backup custody, and migration can reuse one opaque
  artifact substrate while retaining different authority and retention roles.
- Losing every client and every retained root/piece custodian remains data loss;
  the relay does not reconstruct semantic state from opaque messages.
- The root inventory leaks ciphertext working-set equality and approximate
  sizes to the service within one domain. It does not expose plaintext hashes,
  model types, titles, participant identities, or cross-domain equality.

## Implementation order

1. Land the portable root/piece contracts and adversarial validation.
2. Add package-local sealed-piece custody and exact reuse.
3. Replace full checkpoint chunk publication with one root plus pieces.
4. Prove initial capture, incremental capture, recovery, restart, and collection
   below the UI using Device Sync.
5. Add the minimum Device Sync recovery status and replacement-device UI.
6. Reuse the substrate for Shared Space onboarding/recovery and Facets Edge.

This checkpoint does not implement Edge, bridging, Managed/Public Spaces, or
website Companion Space discovery. Those are later consumers of the same
artifact substrate.
