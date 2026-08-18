# Facets Device Sync account bootstrap

Status: server-side bootstrap and opaque Space-domain provisioning vertical
slice. This contract provisions a new Device Sync principal and its first
device, admits additional devices to the opaque principal control-channel
transport, and binds a Facets Space identifier to an isolated relay domain.
Client-side content-trust transfer, account admission UX, Space-domain device
admission, and hosted account integration remain later gates.

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
Device Sync principal, the new device ID, and the principal control-channel
subscription. The server selects the relay capabilities required by the
control-channel transport; callers cannot enlarge them. The principal, domain,
subscription, and relay admission scopes must all match. The product binding
and relay admission commit in one PostgreSQL transaction.

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

## Service isolation

These endpoints are registered only by `facets-device-sync-server`. The Shared
Spaces executable returns `404` for them. Both products reuse the opaque relay
implementation, but Device Sync principal records and admission authority are
not exposed on the Shared Spaces application surface.
