# Replica-message relay API v1

This API is the first durable data plane shared by Facets Sync and Shared
Spaces. It carries the frozen `facets.replica-relay-carrier-fixture.v1`
envelope contract. Facets clients sign and encrypt the complete replica message
before upload; the Node routes the resulting envelope without an FEF parser or
the domain content key.

The API is a development security checkpoint. Public exposure still requires
reviewed TLS ingress, hosted account admission, distributed rate limits,
retention collection, backup/restore proof, and incident procedures.

## Scope and credentials

Every durable relay key includes a random tenant ID and replica-domain ID. A
member adds a random member ID. These are routing scopes, not real-world
identities, email addresses, Personas, or Facets principal identifiers.

Four secrets have distinct authority:

- the operator token provisions a new domain;
- a domain-administration token creates and revokes members;
- each member token exercises only that member's granted capabilities;
- the domain content key remains client-side and encrypts/decrypts messages.

Each token is independently generated as 32 bytes of unpadded base64url. The
Node stores only a domain-separated SHA-256 digest and compares derived digests
in constant time. Do not reuse one secret in another role. Credentials returned
by a provisioning response are shown once and must be placed directly in an
approved client secret store. Send all tokens only as bearer credentials over
TLS.

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
```

This endpoint has no body. It is registered only when
`FACETS_NODE_OPERATOR_TOKEN` is configured. It returns a random tenant/domain,
the domain-administration credential, and an initial member with every currently
defined capability. The default domain bounds are 10,000 messages and 1 GiB of
decoded ciphertext.

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
- `blob_publish` (reserved; no endpoint yet)
- `blob_fetch` (reserved; no endpoint yet)
- `checkpoint_publish` (reserved; no endpoint yet)

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
message-count or decoded-ciphertext-byte limit is reached.

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

## Operations and remaining boundaries

`/livez`, `/readyz`, and `/metrics` have the same private-operations semantics
as the pairing API. The database records domain/member/message scope, monotonic
sequence, credential digests, opaque envelope fields, acknowledgments, and
bounded audit event types. It does not record a content key, decrypted FEF,
Facets package contents, email address, Persona, or payment identity.

This checkpoint does not yet provide administration-token rotation, member
limits, account-wide quotas, retention garbage collection, blob/checkpoint
storage, multi-region replication, online schema rollback, public ingress, or
hosted service-level guarantees.
