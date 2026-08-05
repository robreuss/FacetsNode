# Pairing rendezvous API v1

This API carries the frozen `facets.principal-pairing-rendezvous-fixture.v1`
contract. All payload content is encrypted by Facets clients before upload.

## Authentication

Every route operation uses both headers:

```http
Authorization: Bearer <32-byte unpadded base64url capability>
X-Facets-Rendezvous-Role: sponsor|candidate
```

Sponsor and candidate capabilities are independent. The server derives the
domain-separated SHA-256 digest defined by the portable fixture and compares it
to the stored role digest in constant time. It never stores or logs the bearer
token. Send these headers only over TLS.

The response includes `Cache-Control: no-store` and a random `X-Request-ID`.
Error bodies contain a stable code but no supplied credential, ciphertext, or
database detail.

## Create a route

```http
POST /v1/pairing/routes
Content-Type: application/json
Authorization: Bearer <sponsor capability>
X-Facets-Rendezvous-Role: sponsor
```

The body is `FEFPrincipalPairingRendezvousRegistration` JSON. The route must be
active at the server's current time and may live for at most 15 minutes. The
server verifies that the caller possesses the sponsor capability represented by
the submitted digest. An exact retry returns `200` and `duplicate`; a new route
returns `201` and `accepted`. A route ID can never replace different stored
registration data.

Route creation is intentionally pre-principal and pre-tenant: the device being
paired does not yet have its durable trust relationship. These short-lived,
random, isolated records are the sole Stage 3 durable-key exception. General
Sync and Shared Space stores must include tenant and exchange-domain scope in
every durable key.

## Publish an opaque envelope

```http
PUT /v1/pairing/routes/{routeID}/messages/{messageID}
Content-Type: application/json
Authorization: Bearer <role capability>
X-Facets-Rendezvous-Role: sponsor|candidate
```

The body is `FEFPrincipalPairingRendezvousEnvelope` JSON. Path and body IDs must
match. Nonce, tag, algorithm, timing, and decoded ciphertext size are validated,
but the server cannot decrypt or classify the payload. Ciphertext is limited to
1 MiB and a route to 256 messages.

An exact retry by the same role returns `200` and `duplicate`, including after
the route was closed. Reusing a message ID with any different visible field or
publisher role is a collision. New publication after close is rejected.

## Fetch pending envelopes

```http
GET /v1/pairing/routes/{routeID}/messages
Authorization: Bearer <role capability>
X-Facets-Rendezvous-Role: sponsor|candidate
```

The response is `{"envelopes":[...]}`. Only unexpired, unacknowledged messages
published by the other role are returned, ordered by creation time and message
ID. Fetch is at-least-once; clients acknowledge only after they have durably
accepted the exact envelope locally.

## Acknowledge an envelope

```http
POST /v1/pairing/routes/{routeID}/messages/{messageID}/acknowledgement
Authorization: Bearer <receiver capability>
X-Facets-Rendezvous-Role: sponsor|candidate
```

Successful acknowledgement returns `204` and is idempotent. A publisher cannot
acknowledge its own message.

## Close a route

```http
POST /v1/pairing/routes/{routeID}/close
Authorization: Bearer <sponsor capability>
X-Facets-Rendezvous-Role: sponsor
```

Close is sponsor-only, returns `204`, and is idempotent. It prevents new
messages but preserves fetch, acknowledgement, and exact-retry behavior until
expiry.

## Operations endpoints

- `GET /livez` proves the process can serve HTTP.
- `GET /readyz` proves PostgreSQL is reachable.
- `GET /metrics` emits bounded, label-free OpenMetrics counters. It contains no
  route, message, tenant, credential, or client identifiers.

These endpoints are intended for a private operations network. A public reverse
proxy should expose only the versioned application routes.
