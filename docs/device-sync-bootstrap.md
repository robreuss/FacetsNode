# Facets Device Sync account bootstrap

Status: first vertical slice. This contract provisions a new Device Sync
principal and its first device. Additional-device enrollment, per-Space domain
provisioning, account admission UX, and hosted account integration remain later
gates.

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

## Service isolation

These endpoints are registered only by `facets-device-sync-server`. The Shared
Spaces executable returns `404` for them. Both products reuse the opaque relay
implementation, but Device Sync principal records and admission authority are
not exposed on the Shared Spaces application surface.
