# ADR 0002: Shared Spaces use Private and Secure content-blind profiles

**Status:** Accepted for unreleased development

## Context

Shared Spaces must serve materially different collaboration contexts without
misrepresenting the protection offered by the service. A therapy group, a
closed community that includes minors, and a high-volume public discussion do
not have identical confidentiality, membership, moderation, or operational
requirements.

The shared relay is deliberately not a Facets semantic authority. It can
provide durable routing, cursor delivery, quota enforcement, receipts, audit
facts, and participant administration, but it must not infer content graphs or
possess keys for content-blind Spaces. Security terminology must therefore
describe both cryptographic boundaries and the operational behavior of changes
to membership.

## Decision

The Shared Spaces protocol fixes the following immutable security modes at
Space creation:

1. **Private** is a content-blind E2EE profile for closed, trusted groups. It
   uses a static group-key epoch. Revoking a participant stops future relay
   delivery and authority but cannot revoke a key or content already received.
   Participant rosters remain an administration concern.
2. **Secure** is a content-blind E2EE profile for high-assurance groups. It
   uses device-specific opaque key grants. Revocation atomically advances the
   key epoch and requires a replacement grant for every active device of every
   remaining active participant. Active participants can retrieve the current
   active roster so they can verify operational membership awareness; the
   roster carries no keys, invitations, historical membership, or content.
   Each key grant is
   signed by a host or moderator key already registered in that participant's
   durable authority record; a valid but substituted signing key is rejected.
3. **Managed** remains a reserved protocol mode for a future server-readable,
   high-scale public profile. It is not a current user-facing Shared Space
   option. Its service-managed content custody boundary is distinct from the
   Private and Secure profiles.

The selected mode is immutable. Converting a Space to another profile requires
creating a new Space; unreleased development does not require migration or
compatibility shims.

Across all profiles, participant identity and role authority remain Facets
authority records. Email, payment identity, and display names are contact or
commercial metadata only. Account admission and relay capabilities authorize
delivery, never content decryption.

## Consequences

- Device Sync remains always Secure/content-blind but is not itself a Shared
  Space security profile.
- Shared Spaces may use the common opaque transport-envelope contract, yet all
  client content still reaches canonical Facets storage only through the FEF
  importer. Transport acknowledgements never prove canonical application until
  that transaction commits.
- Secure Spaces incur more membership control traffic and key-distribution
  work than Private Spaces, especially on revocation. That is an intentional
  high-assurance cost, not a reason to weaken Secure semantics.
- A managed public-scale implementation will require separately specified
  policy, membership/integration, moderation, and privacy commitments before
  it is made available.

## Non-goals

- This decision does not implement MLS, public discovery, a universal identity
  server, or a subscription storefront.
- This decision does not make a static Private key safe after an already
  admitted participant has copied it or received content.
- This decision does not place user compute, payment authority, or personal
  identity inside a Shared Space content key hierarchy.
