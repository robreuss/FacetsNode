# Service authority deployment authentication

FacetsNode can enforce the portable Facets service-authority boundary before
normal bearer authorization. Configure all four values for the applicable
service prefix or configure none:

```text
FACETS_DEVICE_SYNC_DEPLOYMENT_ID=<nonzero UUID>
FACETS_DEVICE_SYNC_DEPLOYMENT_SIGNING_KEY_FILE=/run/secrets/facets-device-sync-deployment-key
FACETS_DEVICE_SYNC_DEPLOYMENT_ROUTE_POLICY_FILE=/etc/facets-device-sync/deployment-routes.json
FACETS_DEVICE_SYNC_SERVICE_AUTHORITY_BINDINGS_FILE=/var/lib/facets-device-sync/service-authority-bindings.json
```

Use `FACETS_SHARED_SPACES_...` for the independent Shared Spaces service and
`FACETS_COMPUTE_POOL_...` for the independent Compute Pool Service. Compute
Pool requires all four values. The key file contains exactly one
canonical, unpadded base64url P-256 private
scalar, with an optional final newline. It must be a regular file with no
group or world permissions. The server logs only its public fingerprint.

The packaged Device Sync Compose deployment always supplies all four values.
It mounts independent key and route-policy directories read-only and mounts a
writable authority-state directory at
`/var/lib/facets-device-sync/service-authority`. Before first start, create
`bindings.json` there as `{"bindings":[],"version":1}`, mode 0600, and make
the state directory writable by the container runtime identity (UID 65532).
Mounting the directory, rather than the individual file, is required because
binding activation uses an fsynced temporary file and atomic rename.

The route-policy file is non-secret, operator-owned, and protected from group
or world writes. It contains the exact public deployment descriptor and
transport policy from which the Device Sync operator command signs short-lived
setup offers. Its deployment ID, public signing key, and fingerprint must
match the protected deployment key:

```json
{
  "deployment": {
    "createdAtMilliseconds": 0,
    "deploymentID": "63000000-0000-0000-0000-000000000001",
    "publicSigningKeyX963": "<canonical-unpadded-base64url-P-256-public-key>",
    "routes": [
      {
        "endpoint": "https://facets-box.example:8443",
        "kind": "direct_https",
        "networkScope": "trusted_lan",
        "routeID": "62000000-0000-0000-0000-000000000001",
        "serverAuthentication": { "kind": "web_pki" }
      }
    ],
    "signingKeyFingerprint": "<64-lowercase-hex-characters>",
    "version": 1
  },
  "transportPolicy": {
    "allowsPublicDirectBulkTransfer": false,
    "bulkRouteIDs": ["62000000-0000-0000-0000-000000000001"],
    "controlRouteIDs": ["62000000-0000-0000-0000-000000000001"],
    "messageRouteIDs": ["62000000-0000-0000-0000-000000000001"],
    "version": 1
  },
  "version": 1
}
```

Every endpoint used by `issue-account-admission` must be an exact control
route in this file. The resulting setup link and one-time bearer have the same
expiry, and the link carries the signed offer rather than an unsigned address.

The binding file is non-secret but authority-sensitive. It is an atomic
deployment input with no group/world write permission and this schema:

```json
{
  "bindings": [
    {
      "deploymentID": "63000000-0000-0000-0000-000000000001",
      "digest": "<64 lowercase hexadecimal characters>",
      "revision": 1,
      "scope": {
        "kind": "device_sync",
        "scopeID": "61000000-0000-0000-0000-000000000001"
      }
    }
  ],
  "version": 1
}
```

Duplicate scopes, another deployment ID, malformed digests, unknown fields,
and trailing JSON are rejected at startup. An empty binding list is valid for
a new deployment. The source that
produces this file must first authenticate the corresponding Facets-signed
manifest chain; FacetsNode does not create or repair authority successors.
Device Sync authenticates revision 1 while claiming the first operator
admission. A success response is withheld until the registry has durably
written the public scope, revision, digest, and deployment. If the database
commit succeeds but the binding write fails or the process stops in that
narrow interval, an exact retry repairs the binding and returns duplicate
success; a changed retry fails closed. It then permits only an identical
binding or the next consecutive revision. The Facets authority public key
remains in the client-verified manifest and is not copied into this server-side
binding file.

Once enabled:

- `POST /v1/service-deployment/proof` issues a five-minute deployment-key
  proof only for an exact current scope/revision/digest/deployment binding;
- `POST /v1/service-deployment/bootstrap-proof` accepts a signed, unexpired
  deployment offer and proves live possession of that offered deployment key
  without accepting a Facets bearer;
- all Facets capability routes require the matching protected binding headers;
- after ordinary member-bearer authorization over an authenticated control
  route, the active deployment may issue a transfer grant with a maximum
  five-minute lifetime, bound to the exact current manifest digest,
  deployment, client-selected route, resource, direction, and byte ceiling;
- the configured server process rejects every other service's scope kind, and
  resource-bearing paths require their principal, Space, or relay tenant ID to
  equal the bound logical scope;
- stale or missing authority fails with HTTP 409 before bearer evaluation;
- missing, expired, forged, stale, route-mismatched, cross-resource, wrong-direction,
  or undersized bulk grants fail with HTTP 409 without a direct-route fallback;
- message operations preserve the existing Facets message traffic class and
  do not require a bulk grant; and
- `/livez`, `/readyz`, and `/metrics` remain available to the private
  management plane without a client service scope.

This registry now provides durable Device Sync initial binding activation but
does not yet provide migration orchestration. Shared Spaces initial authority
enrollment and temporary admission-to-scope binding remain later enablement
gates. Compute Pool is a development skeleton, requires deployment
authentication, and does not yet expose onion ingress. Later activation,
migration, and recovery mechanisms must update this same fail-closed registry
rather than introduce another authority source.

The transfer grant is signed by the active deployment key, not the longer-lived
Facets authority key. FacetsNode issues it only after the existing bearer has
authorized the exact relay domain and resource. The client independently checks
the signature against the active deployment in its accepted manifest and
refuses a different route. The route identifier is a client policy binding, not
server-side proof of the physical ingress path; a five-minute replay still needs
the original bearer and is limited to the same opaque resource and byte ceiling.
