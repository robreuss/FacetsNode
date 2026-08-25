# Service authority deployment authentication

FacetsNode can enforce the portable Facets service-authority boundary before
normal bearer authorization. This is an opt-in deployment checkpoint until
the Facets clients provision their initial signed manifests. Configure all
three values for the applicable service prefix or configure none:

```text
FACETS_DEVICE_SYNC_DEPLOYMENT_ID=<nonzero UUID>
FACETS_DEVICE_SYNC_DEPLOYMENT_SIGNING_KEY_FILE=/run/secrets/facets-device-sync-deployment-key
FACETS_DEVICE_SYNC_SERVICE_AUTHORITY_BINDINGS_FILE=/var/lib/facets-device-sync/service-authority-bindings.json
```

Use `FACETS_SHARED_SPACES_...` for the independent Shared Spaces service and
`FACETS_COMPUTE_POOL_...` for the independent Compute Pool Service. Compute
Pool requires all three values; they remain opt-in for the two relay services
until client trust enrollment is complete. The key file contains exactly one
canonical, unpadded base64url P-256 private
scalar, with an optional final newline. It must be a regular file with no
group or world permissions. The server logs only its public fingerprint.

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

Duplicate scopes, another deployment ID, malformed digests, empty bindings,
unknown fields, and trailing JSON are rejected at startup. The source that
produces this file must first authenticate the corresponding Facets-signed
manifest chain; FacetsNode does not create or repair authority successors.
The server permits only an identical retry or the next consecutive revision
when updating its live registry. The Facets authority public key remains in the
client-verified manifest and is not copied into this server-side binding file.

Once enabled:

- `POST /v1/service-deployment/proof` issues a five-minute deployment-key
  proof only for an exact current scope/revision/digest/deployment binding;
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

This registry does not yet provide dynamic binding activation or migration
orchestration. Compute Pool also does not yet expose onion ingress. Those later
mechanisms must update this same fail-closed registry rather than introduce
another authority source.

Initial trust enrollment and temporary admission/rendezvous record-to-scope
binding also remain production-enablement gates. Keep deployment authentication
disabled in a deployed Device Sync or Shared Spaces service until those client
and server paths are wired. Compute Pool is a development skeleton and fails
startup without deployment authentication.

The transfer grant is signed by the active deployment key, not the longer-lived
Facets authority key. FacetsNode issues it only after the existing bearer has
authorized the exact relay domain and resource. The client independently checks
the signature against the active deployment in its accepted manifest and
refuses a different route. The route identifier is a client policy binding, not
server-side proof of the physical ingress path; a five-minute replay still needs
the original bearer and is limited to the same opaque resource and byte ceiling.
