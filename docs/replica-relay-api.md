# Replica relay data plane v1

Facets Node is a content-blind carrier for Personal Sync and future Shared
Spaces. It stores opaque routing identifiers, authorization digests, encrypted
Envelope V1 bytes, and encrypted blobs. It does not parse FEF, principal,
Persona, device, or Space semantics and never receives a domain content key.

The canonical portable contract is
`internal/testfixture/replica-relay-data-plane-portable-v1.json`. Its exact
SHA-256 is `d81b42bc95b1e7adda3ef2ff6c5dbaa471512787481c9fe8b42a563e4b07293f`.
The adjacent lock records the Swift contract input and Envelope schema V1.

## Authority and routing scopes

- `TenantID` groups opaque domains for aggregate quotas. It is not an account.
- `DomainID` is one encrypted replica-message namespace.
- `SubscriptionID` is one logical delivery recipient. It is deliberately
  unrelated to principals, Personas, devices, or Space membership.
- `MemberID` identifies one delivery agent. Several members may serve the same
  subscription.

All bearer tokens are independently generated canonical unpadded base64url
encodings of 32 random bytes. The Node stores only domain-separated SHA-256
digests. Member requests additionally send `X-Facets-Member-ID`.

The tenant digest is lowercase SHA-256 over the bytes
`Facets replica relay tenant provisioning v1\0`, the lowercase tenant UUID,
one NUL byte, and the tenant authorization token.

## Ingress boundary

Private management ingress exposes operator `POST /v1/relay/tenants`,
`/livez`, `/readyz`, and `/metrics`. Checked-in public Caddy ingress exposes
only `/v1/pairing/*` and `/v1/relay/tenants/*`; the exact operator tenant route
has no trailing path and is therefore not matched by the public allowlist.
Deploy public application routes only over HTTPS with certificate validation.

## Provision a tenant and initial domain

```http
POST /v1/relay/tenants
Authorization: Bearer <operator token>
Content-Type: application/json

{
  "version": 1,
  "retryID": "<tenant retry UUID>",
  "tenantProvisioningCredential": {
    "tenantID": "<tenant UUID>",
    "authorizationToken": "<tenant token>"
  },
  "initialDomain": {
    "version": 1,
    "retryID": "<domain retry UUID>",
    "administrationCredential": {
      "tenantID": "<same tenant UUID>",
      "domainID": "<domain UUID>",
      "authorizationToken": "<administration token>"
    },
    "subscriptionID": "<initial subscription UUID>",
    "memberCredential": {
      "tenantID": "<same tenant UUID>",
      "domainID": "<same domain UUID>",
      "memberID": "<member UUID>",
      "authorizationToken": "<member token>"
    },
    "memberCapabilities": ["message_fetch", "message_publish"],
    "createdAtMilliseconds": 1710000000000
  }
}
```

Tenant, initial domain, active subscription, and first member commit atomically.
The response returns acceptance, retry IDs, scope IDs, and authorization
digests; it never echoes bearer secrets. The exact first request returns `201
accepted`; an exact response-loss retry returns `200 duplicate`. Reusing a
tenant, domain, or retry ID with different content fails closed.

Additional domains use the same `initialDomain` body:

```http
POST /v1/relay/tenants/{tenantID}/domains
Authorization: Bearer <tenant provisioning token>
```

There is no domain-to-domain delegated provisioning route or compatibility
fallback.

## Tenant administration

```text
GET  /v1/relay/tenants/{tenantID}/status
POST /v1/relay/tenants/{tenantID}/credential-rotations/{rotationID}
```

Both use the tenant bearer. Status contains only domain/message/blob counts,
separate published and reserved blob counts/bytes, and aggregate count/byte
ceilings. Rotation sends `version`, `rotationID`, `tenantID`,
`replacementAuthorizationDigest`, and `rotatedAtMilliseconds`. It is atomic,
audited, rejects digest reuse, and is exact-retry safe with either side of that
one recorded rotation.

## Subscriptions and delivery agents

Domain-administration bearer routes are:

```text
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/subscriptions
GET  /v1/relay/tenants/{tenantID}/domains/{domainID}/subscriptions/{subscriptionID}
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/subscriptions/{subscriptionID}/status
GET  /v1/relay/tenants/{tenantID}/domains/{domainID}/status
```

Subscription creation is client-identified and exact-retry safe:

```json
{
  "retryID": "<retry UUID>",
  "subscriptionID": "<subscription UUID>",
  "createdAtMilliseconds": 1710000007500
}
```

A new subscription is `active`. Once checkpoints exist, its `startCursor` is
the latest activated checkpoint start cursor; before an activation it is null.
Status change requests contain `retryID`, `status`, and
`changedAtMilliseconds`. Accepted target statuses are
`rebootstrap_required` and `revoked`; every retry ID has immutable
request/result authority. A reset uses a fresh subscription ID so
publisher-subscription exclusion remains correct.

Direct member creation includes the existing active `subscriptionID` plus
capabilities and optional expiry. Admission creation also includes an existing
active `subscriptionID`; it never creates a subscription implicitly. Its
response wraps the admission as `{subscriptionID, admission}` and claim wraps
the member as `{subscriptionID, memberRegistration}`. Revoking a member removes
only that agent. Revoking the subscription removes the logical recipient.

Administration and member credential rotation, admission revocation and
collection, and member revocation retain their existing domain routes. Secrets
are generated by clients; rotations send only replacement digests.

## Messages and acknowledgments

Envelope V1 and the existing authenticated routes are unchanged:

```text
PUT  .../messages/{messageID}
GET  .../messages?cursor=<opaque>&limit=<1...100>
GET  .../messages/wake?cursor=<opaque>&waitMilliseconds=<0...25000>
POST .../messages/{messageID}/acknowledgments
```

Every publication records the publisher subscription. Fetch excludes all
messages published by the caller's subscription, not merely those from the
caller member. Every active subscription is otherwise an independent logical
recipient. Multiple agents serving one subscription may fetch idempotently.

`accepted` and `applied` are monotonic facts keyed by message and subscription.
Any authorized agent may advance them. `applied` requires an existing
`accepted`; an older retry after `applied` returns the higher durable fact.
Periodic cursor fetch is authoritative; wake is only an acceleration hint.

## Checkpoints and bounded collection

A member with `checkpoint_publish` first acquires a server-timed write fence:

```text
POST .../checkpoint-fences
GET  .../checkpoint-fences/{fenceID}
POST .../checkpoint-fences/{fenceID}/abort
```

There is at most one active fence per domain. Its holder is the authenticated
member's subscription, not an identity supplied in the body. While active,
new message publications and blob upload create/chunk/finalize mutations from
other subscriptions fail closed; reads, fetches, acknowledgments, and exact
retries of writes already accepted before the fence continue. Every agent on
the holder subscription may keep publishing the checkpoint suffix. Those
post-boundary messages, and blobs first finalized while the fence is active,
are quarantined from other subscriptions until activation. Fetch cursors stop
at the boundary so a recipient cannot skip the suffix before it becomes
visible. Activation reveals the complete revalidated suffix atomically and
emits a wake hint. Acquisition and abort are exact-retry safe.

The Node supplies the boundary cursor and expiry in the acquisition response.
Expiry uses server receipt time. `FACETS_NODE_CHECKPOINT_FENCE_TTL` defaults to
two hours and is operator-configurable from five minutes through 24 hours. A
longer value gives large encrypted checkpoint uploads more time, but also
extends the maximum foreign-writer pause after a crashed holder. Abort or
expiry releases writes and invalidates any unactivated candidate. Failed-fence
suffixes are never revealed. The Node reclaims up to 10,000 failed message and
blob authorities per serialized fence touch, advances quota counters, and
continues draining on later status/fetch/write operations. Compact message
digest/sequence tombstones and finalization operation records preserve exact
response-loss retries without retaining quarantined ciphertext. Newly finalized
blob authority is queued for the existing grace-period physical reconciler;
pre-fence authority with the same content address is never attributed to or
removed with the fence.

The holder may then stage an opaque checkpoint candidate:

```text
POST .../checkpoints/candidates
```

The candidate contains the fence ID, client-generated `retryID` and
`checkpointID`, its publisher subscription, the exact fence boundary cursor,
sorted complete retained-message and retained-blob ID sets, and a creation
time. Retained messages must be exactly every holder-subscription publication
after the boundary through staging; activation revalidates the same suffix
under the domain lock. Retained blobs must exist but remain opaque and
client-declared. The Node does not interpret checkpoint ciphertext or
application state. Staging is exact-retry safe.

Domain administration controls activation and collection:

```text
POST .../checkpoints/{checkpointID}/activation
POST .../checkpoints/{checkpointID}/collection-dry-run
POST .../checkpoints/{checkpointID}/collection
```

Activation requires the still-active, unexpired fence, returns the boundary as
the checkpoint start cursor, releases the fence atomically, and is exact-retry
safe. It freezes all of the following in one
tenant/domain-serialized PostgreSQL transaction:

- the then-active subscriptions whose custody is required;
- messages at or before the covered-through cursor which are not retained by
  the candidate or the immediately preceding activated checkpoint;
- currently published blobs not retained by either of those checkpoints; and
- the checkpoint start cursor used for later subscription bootstrap.

Publication after that transaction is not part of its deletion set. The exact
holder suffix above the boundary is also outside the covered deletion set. Sequence
allocation remains monotonic after collection. The latest two activated
checkpoints remain retained; older checkpoints are marked retired. Only the
latest activated checkpoint can be collected. When a checkpoint retires, its
large retained/custody/deletion child sets are pruned in the activation
transaction. Its compact candidate digest and operation results remain so
exact stage, activation, and completed collection retries are still durable.

Collection is eligible when each frozen required subscription has accepted or
applied every frozen message it did not publish. A subscription that is now
`rebootstrap_required` or `revoked` no longer blocks custody. There is no
automatic staleness decision for an absent device.

Dry-run returns remaining message/blob counts and bytes, sorted missing-custody
subscription IDs, and a SHA-256 plan digest. Collection requires that digest,
a new exact retry ID, and positive message/blob bounds. Each bound is at most
10,000. A partial collection changes the plan digest, so its next batch must
start with a fresh dry-run. Reusing the exact collection request returns the
recorded result; reusing its retry ID for different input fails closed.

PostgreSQL authority and quota counters commit first, and deleted blob IDs enter
a durable collection queue. The grace-period orphan reconciler re-checks both
published-blob and active-upload authority immediately before physical deletion,
making a same-ID re-publication safe. A new subscription, or one explicitly changed to
`rebootstrap_required`, receives the latest checkpoint start cursor. Resetting
a publisher requires a fresh subscription because a subscription never fetches
its own publications.

## Blobs and quotas

The whole-blob `PUT .../blobs/{blobID}` route has been removed without a
compatibility fallback. Members with `blob_publish` use:

```text
POST  .../blob-uploads
GET   .../blob-uploads/{uploadID}
PATCH .../blob-uploads/{uploadID}
POST  .../blob-uploads/{uploadID}/finalization
```

Create and finalization use client-generated exact retry IDs. `PATCH` carries
raw bytes as `application/octet-stream`, with `Upload-Offset`, `Content-Length`,
and lowercase `X-Chunk-SHA256` headers. Chunks are contiguous. The server fsyncs
staging before advancing the durable PostgreSQL offset; a restart truncates any
uncommitted crash tail back to that offset. Any active member serving the same
subscription may query or resume the upload. Finalization verifies the complete
SHA-256 against the canonical base64url blob ID, publishes atomically, converts
the reservation into published counters, and is exact-retry safe. Published
content remains available through `GET` and `HEAD .../blobs/{blobID}`.

Defaults are:

- per domain: 10,000 messages, 1 GiB message ciphertext, 10,000 blobs, and
  1 GiB blob bytes;
- per tenant: 256 domains, 1,000,000 messages, 1 TiB message ciphertext,
  1,000,000 blobs, and 1 TiB blob bytes;
- per item/page: 16 MiB decoded ciphertext, 256 MiB blob, 100 messages, and a
  25-second wake wait.

Tenant and domain reserved blob counts and bytes advance atomically at upload
creation, preventing concurrent quota oversubscription. Finalization converts
them to published counters. Inactive uploads expire after
`FACETS_NODE_BLOB_UPLOAD_TTL` (seven days by default); physical upload staging
and unreferenced final files are deleted only after
`FACETS_NODE_BLOB_ORPHAN_GRACE` (24 hours by default) and a fresh authority
check.

## Current limits

Cross-instance notifications, distributed rate limits, hosted account admission, and Shared
Space membership/key policy are not implemented in this packet. Checkpoint
collection remains explicitly administration-triggered. No long-absent
subscription becomes stale automatically; revocation or explicit rebootstrap
is required. PostgreSQL and the blob volume remain one coordinated
backup/recovery unit.
