# ADR 0003: Facets authority remains above portable server transport

**Status:** Accepted for unreleased development

## Context

Device Sync and Shared Spaces need location-concealed Tor routes, stable
self-hosted reachability behind NAT, attended deployment migration, and later
client-authorized recovery. A Tor onion identity authenticates a network
service, but it is not Facets principal, device, participant, Space, or content
authority. The existing services already store opaque encrypted carriers and
capability digests without content keys.

## Decision

1. FacetsFEF defines the signed logical service-authority manifest. It binds a
   Device Sync principal or Shared Space to one active deployment, a monotonic
   predecessor chain, and ordered control, message, and bulk routes.
2. FacetsNode never signs, promotes, repairs, or chooses a service-authority
   successor. It may verify and enforce the revision and digest selected by an
   authorized client.
3. A deployment identity and Tor onion identity are independent. Clients
   authenticate the Facets-authorized deployment before sending a reusable
   relay capability. Onion-key possession alone is insufficient.
4. Tor-only ingress is a separate Compose profile with no host-published
   application port. Tor reaches only the reviewed application allowlist over
   a private network. Management, readiness, metrics, PostgreSQL, and blob
   storage remain private.
5. Traffic classification is fixed above transport. Control and ordinary
   messages default to location-concealed routes. Bulk bytes may use an
   authenticated LAN route or an explicitly authorized public direct route
   with a short-lived resource grant.
6. A prepared or standby deployment cannot self-promote. Planned migration and
   recovery require a Facets-authority-signed successor. Conflicting successors
   fail closed.
7. Device Sync and Shared Spaces remain independent services with independent
   databases, blob namespaces, secrets, onion state, quotas, and lifecycle even
   when hosted on one Facets Box.
8. When deployment authentication is enabled, FacetsNode loads its P-256
   deployment key from an owner-only key file and a non-secret, deployment-
   scoped active-binding file. It signs only challenges that name an exact
   current binding. All capability routes reject absent, stale, conflicting,
   or wrong-deployment binding headers before bearer authorization.

## Compromise boundary

An onion-service key compromise can impersonate the route until rotation, but
does not disclose Facets content keys, authorize membership, or sign deployment
authority. A compromised active server can deny service and observe bounded
ciphertext metadata; inner Facets encryption, signatures, checkpoints, and
manifest monotonicity continue to protect content integrity and confidentiality.

## Repository ownership

- Facets owns canonical wire contracts, authority verification, protected
  client custody, route execution, and attended UX.
- FacetsNode owns content-blind HTTP enforcement, deployment readiness, Tor
  ingress, durable opaque storage, and operational backup/restore.
- Shared portable fixtures freeze cross-language fields before Go APIs depend
  on them.

The deployment proof endpoint is deliberately unauthenticated and accepts no
bearer. It proves possession of the manifest-authorized deployment key for a
fresh challenge; it does not grant a capability. Health, readiness, and
metrics remain outside service-scope binding for diagnosis. Every product
capability route becomes fail-closed once deployment authentication is enabled.

No peer-sync compatibility or pre-release route migration is required.

## Consequences

- A mobile client can reach a LAN-hosted onion-only service behind NAT without
  port forwarding; dedicated NAT traversal is needed only for optional direct
  off-LAN bulk transfer and is deferred.
- A provider may host many isolated services on shared infrastructure without
  learning client-visible Sync names or acquiring content-decryption authority.
- Build, PostgreSQL, container, packet-capture, physical-device, migration, and
  recovery results remain distinct verification claims.
