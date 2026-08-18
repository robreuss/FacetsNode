# Facets Device Sync account bootstrap

Status: server-side bootstrap and opaque Space-domain provisioning vertical
slice. This contract provisions a new Device Sync principal and its first
device, admits additional devices to the opaque principal control-channel
transport, binds a Facets Space identifier to an isolated relay domain, and
admits an already enrolled device to that Space transport. Client-side
content-trust transfer, account admission UX, checkpoint/tail orchestration,
and hosted account integration remain later gates.

## Authority boundary

One Device Sync principal maps to one isolated relay tenant. Its protected
principal control channel is the tenant's initial relay domain, and its first
device is the initial member of that domain.

The Facets client creates all principal, tenant, domain, device, and bearer
authority material. The server persists only domain-separated authorization
digests. The operator admission authorizes creation of a service account; it
does not derive, wrap, recover, or receive any content-encryption key. Device
Sync payloads and blobs remain opaque to the service.

## Issue an account admission

An operator or hosted admission service generates a random UUID and independent
32-byte unpadded base64url token. It sends the credential over the private
management surface:

```http
POST /v1/device-sync/account-admissions
Authorization: Bearer <operator-token>
Content-Type: application/json
```

```json
{
  "version": 1,
  "retryID": "<uuid>",
  "admissionCredential": {
    "admissionID": "<uuid>",
    "authorizationToken": "<32-byte-unpadded-base64url>"
  },
  "expiresAtMilliseconds": 0
}
```

`expiresAtMilliseconds` must be between five minutes and seven days after the
server-assigned creation time. The response contains the admission metadata and
its acceptance (`accepted` or `duplicate`), but never echoes the bearer token.
An exact retry is idempotent. Reusing an admission or retry ID for different
material is rejected.

## Claim the admission

The client constructs relay tenant provisioning whose tenant ID equals its new
Device Sync principal ID. The initial domain is its protected principal control
channel, and the initial member ID equals the new Facets device ID.

```http
POST /v1/device-sync/account-admissions/<admission-id>/claim
Authorization: Bearer <account-admission-token>
Content-Type: application/json
```

The request contains the principal ID, initial device ID, tenant-provisioning
credential, control-domain administration credential, subscription ID, and
initial-device member credential. Every bearer is generated independently. The
principal ID must equal every tenant scope; the initial device ID must equal the
control-domain member ID.

The complete request is one PostgreSQL transaction: account admission claim,
relay tenant, control domain, subscription, initial member, Device Sync
principal, and first-device registration either all commit or all roll back.
The admission can create only one principal. An exact response-lost retry
returns `duplicate`; altered reuse returns a conflict.

## Admit another device

An already enrolled device creates a short-lived admission for the new device
on the principal control domain:

```http
POST /v1/device-sync/principals/<principal-id>/control-domains/<domain-id>/device-admissions
Authorization: Bearer <control-domain-administration-token>
Content-Type: application/json
```

The request binds one independently generated relay member admission to the
Device Sync principal, the new device ID, and a fresh device-specific principal
control-channel subscription. A subscription must never be reused by another
device: relay delivery excludes the publisher's own subscription, so sharing a
subscription would silently suppress device-to-device delivery. The server
selects the relay capabilities required by the control-channel transport;
callers cannot enlarge them. The principal and domain scopes must match, and
the server creates the subscription, product binding, and relay admission in
one PostgreSQL transaction.

The new device claims that admission once:

```http
POST /v1/device-sync/principals/<principal-id>/device-admissions/<admission-id>/claim
Authorization: Bearer <device-admission-token>
Content-Type: application/json
```

The claim registers both the relay member and Device Sync device atomically.
Exact response-lost retries return `duplicate`; changed IDs, device material,
or credentials are rejected.

This claim grants transport membership only. It does not make the device a
trusted content principal and does not deliver any content-encryption key. A
currently trusted device must subsequently transfer signed device authority
and key material through the encrypted principal control channel. Until that
client-side step succeeds, the admitted device cannot decrypt or authorize
Device Sync content.

## Inspect content-blind principal status

An authenticated principal can inspect its transport inventory without
exposing Space names, keys, FEF graphs, or payload metadata:

```http
GET /v1/device-sync/principals/<principal-id>/status
Authorization: Bearer <principal-tenant-token>
```

The deterministic response contains only the principal and control-domain IDs,
registered device IDs with their independent control subscriptions, opaque
Space and domain IDs, per-Space device subscriptions, creation times, and any
revocation times. The server reads the inventory in one consistent database
snapshot. This endpoint supports diagnostics and eventual client sync status;
it does not grant transport, content, or decryption authority.

## Revoke an enrolled device

An authenticated principal permanently removes one device from its protected
control channel and every opaque Space domain to which that device was
admitted:

```http
POST /v1/device-sync/principals/<principal-id>/devices/<device-id>/revocation
Authorization: Bearer <principal-tenant-token>
Content-Type: application/json
```

```json
{
  "version": 1,
  "retryID": "<uuid>",
  "principalID": "<principal-id>",
  "deviceID": "<device-id>"
}
```

The Device Sync record, relay members, and device-specific subscriptions are
fenced in one database transaction. No control-channel or Space-domain
membership can remain active after the product revocation commits. An exact
response-lost retry returns `duplicate`; a second revocation with different
retry material is rejected as already revoked.

The account credential selects the Device Sync principal but does not grant
content access or disclose which opaque Space contains what. The content-blind
status inventory reports the resulting revocation times. Because zero-device
key recovery is deferred, the service rejects revocation of the final active
device. At least one enrolled device must remain able to administer the account
and preserve client-held recovery authority.

## Provision an opaque Space domain

An enrolled device provisions one isolated relay domain for each Space selected
for Device Sync:

```http
POST /v1/device-sync/principals/<principal-id>/spaces/<space-id>
Authorization: Bearer <principal-tenant-token>
Content-Type: application/json
```

The request supplies an independently generated domain-administration bearer,
subscription identifier, and initial-device member bearer. The server stores
the opaque Space UUID, relay domain UUID, initial device UUID, and idempotency
metadata. It never receives the Space name, content key, FEF graph, or plaintext
content.

The Device Sync service, rather than the caller, selects the initial member's
transport capabilities and the service's default domain quotas. Product binding
and generic relay-domain creation commit in one PostgreSQL transaction. Exact
response-lost retries return `duplicate`; changed reuse of the Space, retry, or
domain identifier returns a conflict. A generic relay domain that already
exists without a Device Sync binding is rejected rather than adopted.

Space-domain membership is transport authority only. Content trust and keys
remain client-managed. The client acknowledges canonical application only after
the opaque envelope has been decrypted and its FEF content has committed through
the standard Facets importer; server receipt by itself is not application.

## Admit an enrolled device to a Space domain

An enrolled device creates a short-lived admission for another enrolled device
on the selected Space domain:

```http
POST /v1/device-sync/principals/<principal-id>/spaces/<space-id>/domains/<domain-id>/device-admissions
Authorization: Bearer <space-domain-administration-token>
Content-Type: application/json
```

The request binds one relay member admission to the exact Device Sync principal,
opaque Space ID, relay domain, a fresh device-specific subscription, and an
already enrolled device. Per-device subscriptions are mandatory for the same
delivery-isolation reason as the principal control channel. The server creates
the subscription atomically with the product and relay admissions, rejects a
device that is not registered in the principal control domain, and never infers
Space membership from LAN discovery or device names. The server selects the
relay capabilities; callers cannot enlarge them.

The new device claims that Space transport admission once:

```http
POST /v1/device-sync/principals/<principal-id>/spaces/<space-id>/device-admissions/<admission-id>/claim
Authorization: Bearer <space-device-admission-token>
Content-Type: application/json
```

The product Space-device binding and generic relay member registration commit in
one PostgreSQL transaction. Exact response-lost creation and claim retries are
idempotent. Reusing a retry ID, admission ID, or credential for changed Space,
device, domain, or member material is rejected.

This is still transport membership only. A trusted Facets device must deliver
the Space key and signed client-side authority over the encrypted principal
control channel before the newly admitted device can decrypt, apply, or
authorize Space content. The Device Sync server stores no such key or trust
decision.

## Service isolation

These endpoints are registered only by `facets-device-sync-server`. The Shared
Spaces executable returns `404` for them. Both products reuse the opaque relay
implementation, but Device Sync principal records and admission authority are
not exposed on the Shared Spaces application surface.
