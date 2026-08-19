# ADR 0001: Device Sync is a server-backed, content-blind service

**Status:** Accepted for unreleased development

## Context

The earlier Personal Sync prototype used a peer-dependent LAN rendezvous:
another Facets client had to be awake for device joining and later delivery.
That made Device Sync availability depend on Bonjour discovery and an active
peer, while adding a separate topology and lifecycle beside Shared Spaces.

Facets needs one durable, self-hostable and hosted delivery architecture for:

- a person's own devices;
- Shared Spaces; and
- later, space-bound compute routing.

The services have different authority and product semantics, but they can use
the same opaque envelope, blob, receipt, cursor, checkpoint, and tail
foundation.

## Decision

Facets Device Sync is the product implementation for synchronization among a
single user's devices. It is a separately deployable server application, not a
peer-to-peer product mode.

1. The Device Sync service is always content-blind E2EE. It may persist
   encrypted checkpoints, mutation tails, blobs, transport memberships,
   cursors, receipts, and revocations. It never receives a Space content key,
   plaintext FEF, or a semantic graph to reconstruct.
2. One Device Sync principal represents one user's Facets data profile. The
   server can host many isolated principals, including distinct household
   members, without making their membership or content visible to one another.
3. Account/bootstrap authorization admits a principal to the service. It is
   distinct from content-decryption authority. Adding a device requires an
   already trusted device to transfer client-held trust and key material over
   a protected, target-bound control exchange. Zero-device recovery remains
   deferred.
4. Joining Device Sync transfers no Space automatically. Auto-sync and an
   individual Space's enrollment setting remain client policy decisions.
5. The Device Sync service owns no canonical Facets content store. A receiving
   Facets client decrypts an envelope, validates it, and applies FEF only
   through the standard importer. Transport acknowledgement follows durable
   canonical application. Lenses and other rebuildable state are regenerated
   locally after that transaction commits.
6. Device Sync and Shared Spaces remain separate deployable applications with
   independent databases, blob namespaces, quotas, and authority records.
   They share the Go relay foundation and versioned opaque transport contract.
7. The LAN peer-sync/Bonjour implementation is development-only while the
   server-backed client reaches acceptance. It must not be presented as the
   normal Sync product path, and new product work must not depend on it.

## Consequences

- Self-hosting uses the Device Sync Compose application on a Mac, home server,
  VPS, or equivalent host. A hosted Facets offering uses the same service
  binary with managed infrastructure.
- A newly installed device can enroll even while another device is not serving
  network traffic; an existing trusted device is still required for the
  protected authority transfer.
- Existing peer-sync test state and pre-release identities may be discarded.
  No migration or compatibility layer is required for the unreleased product.
- CloudKit or another user-selected append-only storage transport may later
  implement the same encrypted envelope/cursor/receipt contract. It does not
  change Device Sync's authority or canonical-import rules.

## Non-goals

- This decision does not make Shared Spaces server-readable. Shared Spaces
  retains its own immutable E2EE or managed security mode.
- This decision does not introduce a public discovery storefront, billing, or
  compute marketplace.
- This decision does not make a server the source of Facets semantic truth.
