# Blob Storage Adapter Contract

Facets Device Sync and Facets Shared Spaces use the same opaque blob contract.
The server validates transport authorization and metadata; a storage adapter
only provides durable bytes. It must never inspect, decrypt, or reconstruct
FEF content.

## Required data-plane behavior

An adapter implements `relay.BlobContentStore` and
`relay.BlobUploadContentStore`.

- `Put` verifies the content-addressed blob identifier and byte count before
  making the blob durable. Repeating the same `(tenant, domain, blobID)` is
  idempotent.
- `Open` returns the exact committed byte stream and byte count for that
  scoped blob.
- Resumable uploads preserve the server-approved durable offset. Failed or
  invalid chunks must not advance it.
- `Publish` verifies the complete object through `Put`, so a staged upload
  cannot become visible with a mismatched digest or length.

## Required maintenance behavior

An adapter also implements `relay.BlobContentMaintenanceStore` and
`relay.BlobUploadMaintenanceContentStore`. It enumerates opaque candidates
and deletes a candidate only from the callback passed by `BlobMaintenanceStore`.
The relational authority is rechecked immediately before deletion; a storage
listing alone never authorizes reclamation.

The local filesystem adapter is one implementation. A hosted object-storage
adapter may use object listings and multipart-upload state, but must retain the
same scoped identifiers, idempotence, integrity checks, and recheck-before-
delete behavior.
