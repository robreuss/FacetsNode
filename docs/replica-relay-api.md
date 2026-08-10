# Replica-message relay API v1

This API is the first durable data plane shared by Facets Sync and Shared
Spaces. It carries the frozen `facets.replica-relay-carrier-fixture.v1`
envelope contract plus independently encrypted, content-addressed blob bytes.
Facets clients sign and encrypt the complete replica message before upload; the
Node routes its envelope and blobs without an FEF parser or the domain content
key.

The API is a development security checkpoint. Public exposure still requires
reviewed TLS ingress, hosted account admission, distributed rate limits,
retention collection, backup/restore proof, and incident procedures.

## Scope and credentials

Every durable relay key includes a random tenant ID and replica-domain ID. A
member adds a random member ID. These are routing scopes, not real-world
identities, email addresses, Personas, or Facets principal identifiers.

Five secrets have distinct authority:

- the operator token authorizes an exact new domain registration;
- a domain-administration token creates and revokes members;
- a one-time member-admission token can create one member with frozen
  capabilities before a bounded expiry;
- each member token exercises only that member's granted capabilities;
- the domain content key remains client-side and encrypts/decrypts messages.

Each token is independently generated as 32 bytes of unpadded base64url. The
Node stores only a domain-separated SHA-256 digest and compares derived digests
in constant time. Do not reuse one secret in another role. Provisioning
credentials are generated in an approved client secret store and sent once in
the TLS-protected provisioning request; the response echoes them so the client
can verify the exact registration. Other tokens are sent only as bearer
credentials over TLS.

Member requests also identify the member in a header:

```http
Authorization: Bearer <member token>
X-Facets-Member-ID: <member UUID>
```

Administration requests use the administration bearer token and omit the
member header. Responses include `Cache-Control: no-store` and a random
`X-Request-ID`. Logs use bounded route patterns and exclude supplied IDs,
headers, bodies, ciphertext, tokens, and client IP addresses.

## Provision a domain

```http
POST /v1/relay/domains
Authorization: Bearer <operator token>
Content-Type: application/json

{
  "administrationCredential": {
    "tenantID": "<tenant UUID>",
    "domainID": "<domain UUID>",
    "authorizationToken": "<32-byte unpadded base64url token>"
  },
  "memberCredential": {
    "tenantID": "<same tenant UUID>",
    "domainID": "<same domain UUID>",
    "memberID": "<member UUID>",
    "authorizationToken": "<independent 32-byte token>"
  },
  "memberCapabilities": [
    "message_publish", "message_fetch", "message_acknowledge"
  ],
  "createdAtMilliseconds": 1786381200000
}
```

This endpoint is registered only when `FACETS_NODE_OPERATOR_TOKEN` is
configured. The authorized client generates and durably retains one exact
request before sending it. The Node validates both credentials, their common
scope, the requested capabilities, and the stable creation time; it controls
the domain quotas. The default bounds are 10,000 messages, 10,000 blobs, and 1
GiB shared by decoded message ciphertext and stored blob bytes.

The first exact request returns `201` with `"acceptance":"accepted"`. Replaying
the same request returns `200` with `"acceptance":"duplicate"` and the same
domain, member, and credentials. Reusing the tenant/domain identity with any
different field fails closed as a collision. This lets a client recover from a
lost response without creating a second routing authority or requiring the Node
to retain plaintext credentials.

The operator endpoint is a deployment control-plane seam, not hosted account
admission. Keep it off public application ingress. A later hosted layer will
authorize this operation from account, plan, and billing state.

## Create a member

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members
Content-Type: application/json
Authorization: Bearer <domain-administration token>

{
  "capabilities": ["message_acknowledge", "message_fetch"],
  "expiresAtMilliseconds": 1798761600000
}
```

Expiry is optional. Capabilities are deduplicated and stored in canonical order.
The response contains the random member registration and its bearer credential.
Defined capabilities are:

- `message_publish`
- `message_fetch`
- `message_acknowledge`
- `blob_publish`
- `blob_fetch`
- `checkpoint_publish` (reserved; no endpoint yet)

Direct member creation is appropriate for a private control plane that can
deliver the response directly to an approved secret store. Do not give the
domain-administration token to a joining device. Use a member admission when a
joining client must establish its own member credential.

## Rotate a routing credential

The client generates a replacement token locally, computes its ordinary
domain-separated authorization digest, and sends only the new digest. The
rotation UUID is a client-generated idempotency key:

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/administration/credential-rotations/{rotationID}
Content-Type: application/json
Authorization: Bearer <current domain-administration token>

{"authorizationDigest":"<new administration-token digest>"}
```

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members/{memberID}/credential-rotations/{rotationID}
Content-Type: application/json
Authorization: Bearer <current member token>
X-Facets-Member-ID: <same member UUID>

{"authorizationDigest":"<new member-token digest>"}
```

The digest replacement and rotation record commit atomically. A new rotation
returns `201 accepted`. If the response is lost, the exact request may be
retried with either the previous or replacement token and returns `200
duplicate` with the original rotation time. The previous token cannot perform
any other operation after the commit. Reusing a rotation ID with different
content or reintroducing any prior digest is rejected.

Member rotation is self-service and does not change the member ID,
capabilities, Facets principal/Persona, content key, or Space role. A lost
member token is recovered by revoking that member and admitting a replacement,
not by asking the relay to disclose or reset its secret.

## Issue a one-time member admission

The admitting client generates a random admission ID and independent 32-byte
admission token locally, computes the domain-separated authorization digest,
and sends only the ID and digest to the Node:

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions
Content-Type: application/json
Authorization: Bearer <domain-administration token>

{
  "admissionID": "33333333-3333-4333-8333-333333333333",
  "authorizationDigest": "6d0f62f5a34571b5aee55a85e6e46c3e702f213201400f538c4552b17f8fbafe",
  "capabilities": ["blob_fetch", "message_acknowledge", "message_fetch"],
  "expiresAtMilliseconds": 1710000000000,
  "memberExpiresAtMilliseconds": 1800000000000
}
```

Admission expiry is mandatory and may be no more than seven days after
creation. Member expiry is optional; when present it must follow admission
expiry so a successful claim cannot create an already expired member.
Capabilities and member expiry are frozen at admission creation. An exact
creation retry made while the admission remains issuable returns the original
record and its current claimed or revoked state; reusing an admission ID with
different authority is a collision.

The admission token must be delivered through an authenticated, user-approved
channel. For Personal Sync or an end-to-end encrypted Shared Space, that
channel must separately convey or authorize the client-held content key. The
Node never receives that key. Possession of an admission token grants only the
listed relay capabilities; it is not proof of a durable Facets principal,
device grant, Persona, subscription, or Space membership.

The admission-token digest is:

```text
SHA-256(
  "Facets replica relay member admission v1\0" ||
  lowercase(tenantID) || "\0" ||
  lowercase(domainID) || "\0" ||
  lowercase(admissionID) || "\0" ||
  admissionToken
)
```

The versioned
`internal/testfixture/relay-member-admission-portable-v1.json` fixture freezes
this digest, the existing member-token digest, and both request bodies for
independent client implementations.

## Claim a member admission

The joining client independently generates its random member ID and member
token, computes the existing member-authorization digest, stores both secrets
locally, and sends only the member ID and digest in the claim body:

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/claim
Content-Type: application/json
Authorization: Bearer <member-admission token>

{
  "memberID": "44444444-4444-4444-8444-444444444444",
  "authorizationDigest": "7c17f23651cc8a3e9823393ba6995b858fc3ba570aaef56e2a3d1ca26fb7aa8f"
}
```

The Node atomically consumes the admission and creates the member. It never
stores either plaintext bearer token. An exact retry with the same member ID
and digest returns the original member after admission expiry, allowing a
client to recover from response loss during the 30-day recovery window. A
different second claim is rejected.

An unclaimed admission can be cancelled idempotently:

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/{admissionID}/revocation
Authorization: Bearer <domain-administration token>
```

After claim, revoke the resulting member instead. Revoking an admission does
not revoke a member that was already created from it.

Terminal admission rows are retained for at least 30 days from claim,
revocation, or unclaimed expiry so exact claim retries remain recoverable. An
administrator then collects at most 256 eligible rows per call:

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/admissions/collection
Authorization: Bearer <domain-administration token>
```

The response reports `collectedCount`, `hasMore`, and
`eligibleBeforeMilliseconds`. Collection deletes the admission credential
record but preserves its typed audit event. A collected admission is no
longer retryable.

## Authority bounds

This checkpoint applies hard self-hosted safety bounds independently of later
hosted plans and billing quotas:

- 256 active and 4,096 retained members per domain;
- 64 outstanding and 4,096 retained admissions per domain;
- 256 retained credential rotations per subject and 4,096 per domain;
- 256 admission rows collected per request after a 30-day recovery window.

Exact retries are evaluated before capacity checks. Expiry or revocation frees
an active/outstanding slot without erasing the retained authority record.

## Revoke a member

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/members/{memberID}/revocation
Authorization: Bearer <domain-administration token>
```

Revocation is immediate for subsequent authorization checks and idempotent.
The result is `accepted` on the first call and `duplicate` thereafter. It does
not delete existing messages or erase audit facts.

## Publish an opaque message

```http
PUT /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}
Content-Type: application/json
Authorization: Bearer <member token>
X-Facets-Member-ID: <publisher member UUID>
```

The JSON body is the complete outer relay envelope. Path, envelope, and member
credential scopes must agree. The Node validates only visible framing:
algorithm, random IDs, key epoch, creation time, canonical base64url fields, a
12-byte nonce, a 16-byte authentication tag, and ciphertext size. Ciphertext is
limited to 16 MiB per message.

The Node assigns a strictly increasing sequence within the domain. A new
message returns `201` with `accepted` and its sequence. An exact retry by the
same publisher returns `200` with `duplicate` and the original sequence, without
charging the quota again. Reusing a message ID with any different visible field
is a collision. Publication stops with `domain_full` when either the domain's
message-count or total stored-byte limit is reached.

The envelope has no server-enforced expiry. Offline catch-up and device
recovery therefore do not depend on client clock agreement. Retention and
deletion are server policy, but collection is not implemented in this
checkpoint.

## Fetch with an opaque cursor

```http
GET /v1/relay/tenants/{tenantID}/domains/{domainID}/messages?cursor={cursor}&limit=100
Authorization: Bearer <member token>
X-Facets-Member-ID: <member UUID>
```

An absent cursor starts at the beginning. `limit` defaults to 100 and cannot
exceed 100. The response contains ordered `messages` plus a new opaque `cursor`.
The cursor records progress through a stable high-water mark, including
sequences skipped because they were published by the caller. Clients must not
decode, edit, compare, or synthesize cursors; persist the last cursor only after
durably accepting the corresponding page.

Publishers do not fetch their own messages. Fetch is at-least-once across
client failures: replaying an older cursor can return the same envelopes again,
and message identity makes local application idempotent.

## Record accepted and applied facts

```http
POST /v1/relay/tenants/{tenantID}/domains/{domainID}/messages/{messageID}/acknowledgments
Content-Type: application/json
Authorization: Bearer <member token>
X-Facets-Member-ID: <member UUID>

{"stage":"accepted"}
```

`accepted` means the receiving replica durably owns the exact encrypted
message. `applied` means replica processing durably incorporated it. A member
must record `accepted` before `applied`; it cannot acknowledge its own message.
Repeated or lower-stage requests are idempotent and return the highest stored
stage. Acknowledgments are per-member facts and do not currently trigger
deletion.

## Store and fetch an encrypted blob

The signed plaintext artifact refers to source bytes, but its encrypted relay
payload privately maps each source ID to the SHA-256 content address of a
separately encrypted blob. The server sees only that relay blob ID and the
encrypted bytes. It cannot associate a blob with a particular message or source
file from the outer carrier.

```http
PUT /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{relayBlobID}
Content-Type: application/octet-stream
Content-Length: <required byte count>
Authorization: Bearer <member token>
X-Facets-Member-ID: <publisher member UUID>
```

The relay blob ID is canonical unpadded base64url for the 32-byte SHA-256 digest
of the exact encrypted request body. Upload is streamed to a staging file; the
Node enforces a 256 MiB per-blob maximum, verifies the declared length and
digest, syncs the file, and atomically links it into a tenant/domain-scoped
content store. A new metadata record returns `201` and `accepted`; an exact
content-addressed retry returns `200` and `duplicate` without charging quotas
again. Blob count and bytes share the domain's transactional quota counters with
messages.

Because the relay ID is a ciphertext content address, clients must use
randomized, domain-bound authenticated encryption and avoid ciphertext reuse
across domains. The filesystem path is domain-scoped, but an operator could
still correlate an identical relay ID submitted to two domains.

Authorization and capacity are checked before receiving bytes and again before
metadata commit. Revocation, expiry, or a quota race during transfer therefore
fails closed. Because the immutable file is committed before its database fact,
a database failure at that final boundary can leave an inaccessible orphan; a
retry heals the record, while automated orphan collection remains pending.

```http
GET /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{relayBlobID}
HEAD /v1/relay/tenants/{tenantID}/domains/{domainID}/blobs/{relayBlobID}
Authorization: Bearer <member token>
X-Facets-Member-ID: <member UUID>
```

The response is `application/octet-stream`, includes the quoted relay blob ID
as its immutable `ETag`, and supports standard single or multipart HTTP byte
ranges through `Range`. This permits interrupted downloads to resume. Uploads
are currently whole-blob and idempotent: an interrupted upload must restart.
Multipart/resumable upload is a later storage packet.

Self-hosted Compose stores these bytes in a separate named filesystem volume
behind a narrow content-store interface; PostgreSQL holds authority, quota, and
audit metadata only. Hosted multi-instance operation requires an object-store
adapter and is not implied by the filesystem checkpoint. Backups and restores
must treat the database and blob store as one coordinated checkpoint.

The live delivery-matrix integration gate exercises the contract through HTTP
and the real PostgreSQL/filesystem stack. It covers exact message retries,
replayed cursors, delayed and concurrently published traffic, independent
recipient progress and acknowledgments, a truncated upload followed by a full
retry, exact blob retry, and cross-member download. Restart persistence remains
proved independently at the PostgreSQL-store and persistent-Compose gates; the
HTTP matrix does not control or assume a particular service supervisor.

## Operations and remaining boundaries

`/livez`, `/readyz`, and `/metrics` have the same private-operations semantics
as the pairing API. The database records domain/admission/member/message/blob
scope, monotonic sequence, current and prior credential digests, rotation
idempotency facts, opaque envelope fields, byte counts, acknowledgments, and
bounded audit event types. It does not record a content
key, decrypted FEF, plaintext package contents, email address, Persona, or
payment identity.

This checkpoint does not yet provide operator-token rotation, account-wide
quotas, message/blob retention or orphan garbage collection, resumable upload,
checkpoints, hosted object storage,
multi-region replication, online schema rollback, public ingress, or hosted
service-level guarantees.
