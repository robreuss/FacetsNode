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
the key, policy, and state directories and their files owned by the container
runtime identity (UID 65532). Keep each directory mode 0700 and each file mode
0600; the key and policy mounts remain read-only while the state mount is
writable.
Mounting the directory, rather than the individual file, is required because
binding activation uses an fsynced temporary file and atomic rename.
The persistent authority registry currently requires Unix `flock` semantics;
native Windows hosting fails closed until a `LockFileEx` adapter is implemented.
Run the service in its Linux container on Windows hosts.

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
      "manifest": {
        "payload": "<canonical signed manifest payload>",
        "signature": {
          "algorithm": "ES256",
          "publicSigningKeyX963": "<canonical base64url public key>",
          "signature": "<canonical base64url raw signature>",
          "signerID": "<Facets authority UUID>",
          "signingKeyFingerprint": "<64 lowercase hexadecimal characters>"
        }
      },
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

Duplicate scopes, a deployment ID not authorized for the local host by the
signed manifest, malformed digests, unknown fields, and trailing JSON are
rejected at startup. An empty binding list is valid for
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

The persistent registry normalizes the configured path and obtains an
exclusive process-lifetime lock before reading it. Only one FacetsNode process
may own a binding file; another loader fails closed until the owner invokes
`Close`. Unix builds use an operating-system file lock. The future Windows
adapter still requires a native interprocess lock; loading a persistent
registry currently fails unsupported there. The lock file must remain a
private regular file in the owner-controlled binding directory.

An attended migration enriches the same entry with the exact signed manifest.
The active `deploymentID` may then name the other deployment only while that
manifest still names the local deployment as the migration source, target, or
prepared deployment. A fenced exporter also persists `writeFence`, containing
the authority revision/digest, canonical snapshot payload, and—after
signing—the exact deployment-signed snapshot and reference digest. A staged
but not yet signed fence is valid and blocks writes after restart. Preparation,
activation, and rollback bindings also retain a domain-separated digest of the
complete accepted evidence so only an exact expired retry remains idempotent.

Migration snapshot signing is deliberately two-phase. The service state store
first commits its state commitment and write-fence identifier; the registry
then durably stages that exact canonical payload and blocks mutating HTTP
requests. Only the registry's staged-snapshot signer may use the deployment
key. Activation and rollback require complete migration evidence and cannot be
installed through the generic binding or successor methods. Exact retries are
idempotent; conflicting payloads, signatures, revisions, or fences fail.
The HTTP gate does not drain a write already inside a backend transaction;
service-specific stores must enforce the same fence transactionally before a
runtime migration claim is valid.

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

This registry now provides durable Device Sync initial binding activation,
portable attended-migration evidence validation, successor persistence, and a
fail-closed two-phase write-fence/signing boundary. It does not yet provide
public migration routes, service-state/blob copy orchestration, onion-state
handoff, operator cutover, or deployed rollback. Shared Spaces initial
authority enrollment and temporary admission-to-scope binding remain later
enablement gates. Compute Pool is a development skeleton, requires deployment
authentication, and does not yet expose onion ingress. Recovery remains
fail-closed and must use this same registry rather than introduce another
authority source.

The transfer grant is signed by the active deployment key, not the longer-lived
Facets authority key. FacetsNode issues it only after the existing bearer has
authorized the exact relay domain and resource. The client independently checks
the signature against the active deployment in its accepted manifest and
refuses a different route. The route identifier is a client policy binding, not
server-side proof of the physical ingress path; a five-minute replay still needs
the original bearer and is limited to the same opaque resource and byte ceiling.
