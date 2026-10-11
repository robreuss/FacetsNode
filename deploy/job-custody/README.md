# Job Custody service profile

This Compose application packages the content-blind Job Custody service. The
shared physical Storage Capacity Authority it consumes has a separate Compose
application, database, credentials, network boundary, and lifecycle. The Box
Controller receives only Job Custody health and coarse admission readiness;
it receives neither database credential nor Storage Capacity authority.

The profile is architecture-neutral and builds for the host selected by the
container runtime. Source/build success is not deployment acceptance on the
primary VM, FBD, or the Raspberry Pi prototype.

## Provisioning boundary

1. Copy `.env.example` to `.env` and replace every placeholder.
2. Create the configured directories on the retained data filesystem. Keep
   the deployment key, route policy, admission trust, and capacity TLS
   certificate independent. Job Custody content is bind-mounted from
   `FACETS_BOX_DATA_ROOT/job-custody/content`; it must be writable only by
   container UID 65532. The container runtime data root that holds PostgreSQL
   must remain on the same physical filesystem.
3. Install and initialize `deploy/storage-capacity` for the exact retained
   physical pool. Its private `facets-box-storage-capacity-client` network and
   TLS endpoint must be healthy before Job Custody starts.
4. Start the Device Sync/Box Controller Compose application first so the
   external `facets-box-service-control` network exists. Configure its paired
   `FACETS_BOX_JOB_CUSTODY_PRIVATE_URL=http://job-custody:8080` and
   `FACETS_BOX_JOB_CUSTODY_URL` values.
5. Start this profile with `docker compose up -d` and verify health before
   advertising the public route.

The main Box ingress exposes only `/facetsbox/job-custody/v1/job-custody/*`.
Operational health and admission readiness remain on the private
`facets-box-service-control` network. The Storage Capacity Authority is further
isolated in its own deployment behind a private TLS terminator and has no
host-published port.

The private certificate must be valid for the Compose DNS name
`storage-capacity`. Job Custody mounts only its public certificate through
`SSL_CERT_FILE`; the capacity TLS private key is present only in the Caddy
terminator.
