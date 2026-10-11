# Storage Capacity Authority service profile

This Compose application owns one content-blind physical-capacity authority
for one retained filesystem. It is shared infrastructure, not part of Job
Custody, Backup, Device Sync, or another service's deployment lifecycle.
Every client keeps its own quotas and authenticates each exact capacity call
with its independently provisioned deployment identity.

The profile is architecture-neutral. Building it for AMD64 or ARM64 does not
establish runtime acceptance on the primary VM, FBD, or the Raspberry Pi.

## Initialization

1. Copy `.env.example` to `.env` and replace every placeholder.
2. Create `capacity-pool` beneath `FACETS_BOX_DATA_ROOT`. It must be a
   content-free sentinel directory on the same physical filesystem as the
   services and container data being arbitrated.
3. Provision `peers.json` with the immutable deployment identity and public
   signing key of every allowed capacity client. Do not place service database
   credentials, paths, account, Space, Job, or object identities in it.
4. Provision an independent TLS certificate valid for `storage-capacity`.
5. Start PostgreSQL and initialize the exact physical pool once:

   ```sh
   docker compose up -d postgres
   docker compose --profile initialize run --rm initialize
   ```

6. Start the authority with `docker compose up -d`. Ordinary startup refuses
   to invent or replace the retained pool identity.

The authenticated API is terminated at private TLS and exposed only on the
internal named network `facets-box-storage-capacity-client`. It has no
host-published port. Client services mount only `server.crt`; the TLS private
key remains in the capacity terminator.
