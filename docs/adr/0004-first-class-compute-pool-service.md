# ADR 0004: Compute Pool Is an Independent Facets Service

**Status:** Accepted for unreleased development

## Context

The initial Shared Spaces compute slice stores `ComputePool` beside its
`SpaceComputeBinding`, keys both records by `space_id`, and deletes the Pool
when that Space is deleted. Facets now requires a durable Pool to serve local
and Shared Spaces, run on a device, Facets Box, VPS, or hosted infrastructure,
and reuse portable Tor/direct service authority.

The current signed Space compute capability remains useful, but its Pool is not
yet an independent authority and its claims assume every caller is a Shared
Space participant with a content-key epoch.

## Decision

1. The Go codebase produces a third independently deployed Facets Compute Pool
   Service beside Device Sync and Shared Spaces.
2. `compute_pool` is a portable service-authority scope. It has independent
   deployment identity, onion state, credentials, database, blob namespace,
   quotas, backup, migration, and recovery lifecycle.
3. `ComputePool` has a Pool ID and owner-authority revision; it contains no
   `SpaceID` and is never stored in the Shared Spaces database.
4. `SpaceComputeBinding` is stored by the applicable Space authority and
   references a Pool ID plus the accepted Pool authority anchor or manifest.
   Space-to-Pool is many-to-many and has no cross-database foreign key.
5. Shared Spaces authorizes a bounded invocation from current membership and
   Space policy. Compute Pool independently admits it under current Pool,
   offering, capacity, budget, and Worker policy. Neither signature replaces
   the other.
6. Worker enrollment, Worker consent, offering disclosure, management
   identity, and execution identity remain independent of Space membership.
7. Workers receive job-scoped inputs and keys only. Compute Pool remains an
   opaque durable carrier for encrypted inputs/results and does not parse FEF or
   write a Space package.
8. The existing Space-owned Pool tables, routes, and error names are replaced,
   not migrated, because Facets is unreleased.

## Repository boundary

Facets owns canonical portable authority, binding, job, and provenance
contracts. FacetsNode owns Pool deployment enforcement, durable opaque custody,
Worker/offer admission, retry and acknowledgement behavior, quotas, and
operational recovery. Shared fixtures freeze field names and canonical
signatures before an HTTP API or persistent schema depends on them.

## First delivery slice

- extend service authority with `compute_pool`;
- introduce independent Pool, offering, Worker-enrollment, and Pool-admission
  package contracts;
- replace Shared Spaces Pool ownership with a binding-only store and route;
- add separate Pool migrations and an executable/configuration skeleton; and
- prove that deleting either side cannot mutate the other authority.

Job scheduling, provider adapters, billing, marketplace discovery, full UI,
sealed-compute enforcement, and autonomous agent behavior remain deferred.
