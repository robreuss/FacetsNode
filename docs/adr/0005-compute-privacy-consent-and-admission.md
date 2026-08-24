# ADR 0005: Compute Privacy, Consent, and Admission Are Exact Evidence Chains

**Status:** Accepted for unreleased development

## Context

Compute Pools may contain Facets-managed local runtimes, separate local
processes, private infrastructure, and external providers. A Pool or Worker
cannot truthfully collapse those boundaries into one trust score. Likewise, a
participant's consent cannot weaken a hard Space commitment, silently select a
less-private offering, or authorize payloads other than the exact content that
was reviewed.

The first Compute Pool contract used free-form retention, training, and
sensitivity strings. Those strings were not adequate inputs for deterministic
admission, mixed-selection partitioning, or an auditable job lifecycle.

## Decision

1. Compute Pool wire schema version 2 replaces version 1 without compatibility
   decoding or migration. Facets is unreleased.
2. Privacy class, data-handling, data-use, resource, and budget constraints are
   structured and closed. Unknown model types remain client-classified as
   Confidential; FacetsNode remains content-blind.
3. Worker Cards contain factual assurance dimensions and evidence kinds. Pool
   offerings bind an exact Worker Card ID, revision, and canonical digest.
   Facets computes suitability language; operators do not supply a signed
   marketing score.
4. A client invocation authorization binds the request and payload digests,
   disclosure-plan evidence, privacy class, Worker Card, and offering revision.
   A Pool admission independently binds that authorization to one Worker,
   resource ceiling, budget ceiling, expiry, and lease.
5. Worker execution and client result-application receipts form separate
   signed evidence. A Pool-authored transition chain cannot reach `completed`
   before a verified `result_applied` transition.
6. Exact duplicate transitions and receipts are idempotent. Same-identity or
   same-sequence records with different canonical digests fail closed.
   `cancel_requested` is not final; only a later signed `cancelled`, `failed`,
   or `expired` transition confirms termination.
7. Private or Secure Space policy weakenings remain pending while any active
   participant has not signed the exact proposed policy revision and digest.
   Strengthenings activate immediately. Consent never overrides a prohibited
   Space control.
8. Remembered consent is local, narrow, and limited to Public or Personal data
   for at most 30 days. It binds object scope, selected fields, audience,
   policy and roster evidence, provider, Worker Card, and offering revision.
9. This checkpoint adds no public job, blob, scheduling, interactive-session,
   or provider route. Scheduling remains client-owned and must obtain fresh
   evaluation and admission when it fires.

## Authority and privacy boundary

Facets owns model defaults, object/component classification, disclosure-plan
evaluation, local trust preferences, consent UX, and package-local audit
commit. FacetsNode may verify and persist only the signed facts required for
Pool or Space authority decisions. It does not receive revealing client-facing
template labels, inspect FEF plaintext, reclassify content, or turn operator
claims into stronger evidence.

Worker, Worker owner, Pool, Space, participant device, deployment, and
transport identities remain distinct. Tor changes reachability and network
metadata exposure; it does not replace any identity or evidence in this chain.

## Deferred work

Production disclosure interception and atomic package audit, encrypted job and
blob routing, key release, provider adapters, interactive inference, scheduling
execution, billing, UI, deployment, and physical-device acceptance remain
separate checkpoints.
