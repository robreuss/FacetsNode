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

Use `FACETS_SHARED_SPACES_...` for the independent Shared Spaces service. The
key file contains exactly one canonical, unpadded base64url P-256 private
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
when updating its live registry.

Once enabled:

- `POST /v1/service-deployment/proof` issues a five-minute deployment-key
  proof only for an exact current scope/revision/digest/deployment binding;
- all Facets capability routes require the matching protected binding headers;
- the configured server process rejects the other service's scope kind, and
  resource-bearing paths require their principal, Space, or relay tenant ID to
  equal the bound logical scope;
- stale or missing authority fails with HTTP 409 before bearer evaluation; and
- `/livez`, `/readyz`, and `/metrics` remain available to the private
  management plane without a client service scope.

This checkpoint does not yet provide dynamic binding activation, Tor ingress,
or migration orchestration. Those later mechanisms must update this same
fail-closed registry rather than introduce another authority source.

Initial trust enrollment and temporary admission/rendezvous record-to-scope
binding also remain production-enablement gates. Keep deployment authentication
disabled in a deployed service until those client and server paths are wired.
