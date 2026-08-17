# Facets Node

Facets Node is the open-source, self-hostable store-and-forward service for
Facets Sync and Shared Spaces. The project is a Go modular monolith packaged as
an OCI image. Hosted Facets infrastructure and a user's own server run the same
protocol implementation.

The implemented roles are an attended device-pairing rendezvous and the first
general replica-message relay. They store only random routing identifiers,
domain-separated capability digests, bounded metadata, and client-encrypted
envelopes. Pairing payload kinds, FEF messages, principal IDs, device IDs, key
material, and bearer capabilities are never stored in plaintext.

This repository is intentionally separate from the Facets application. Relay
development after a shared-contract freeze does not require changes to the
Facets core codebase.

## Current scope

- PostgreSQL-backed, restart-safe pairing routes and opaque envelopes
- Separate sponsor and candidate bearer capabilities
- Exact-retry idempotence and message-ID collision rejection
- Role-separated fetch, receiver acknowledgement, expiry, and sponsor close
- Request limits, timeouts, structured redacted logs, health, and metrics
- Local Compose profile, a single production OCI image, and HTTPS application
  ingress separated from loopback-only management ingress
- Cross-language tests against the public Swift rendezvous fixture
- Explicit tenant, replica-domain, and member scope on every relay operation
- Capability-scoped relay membership with immediate expiry and revocation
- One-time, expiry-bound member admissions that never expose domain
  administration credentials to joining clients
- Atomic, response-loss-safe tenant/domain/member credential rotation with old-secret
  reuse rejection and bounded history
- Client-generated tenant provisioning authority for additional domains
- Bounded active/retained members and admissions, plus administrator-driven
  collection after a 30-day admission retry window
- Opaque subscriptions with multiple delivery agents and subscription-level
  monotonic accepted/applied facts
- Disposable domain change hints that accelerate, but never replace, cursor polling
- Separate per-domain and tenant-wide message/blob count and byte quotas
- PostgreSQL-backed concurrent publication with restart-safe ordering
- Live delivery-matrix proof for cursor replay, delayed and concurrent traffic,
  independent recipients, acknowledgment progression, and interrupted uploads
- Cross-language tests against the public Swift replica-carrier fixture
- Domain-scoped, content-addressed encrypted-blob storage on a separate volume
- Streaming blob upload with digest verification and Range-capable GET/HEAD

Resumable/multipart blob upload, checkpoints, message/blob retention and orphan collection,
hosted object storage/account admission, Shared Space membership, billing, and
compute are later modules. Relay member admission grants routing authority
only; it does not verify identity or carry a domain content key. The checkpoint
capability name is reserved but its endpoint is not yet implemented. No valid
FEF, device grant, payment record, or Shared Space membership will implicitly
grant compute execution.

Operator provisioning atomically creates a tenant, a client-generated private
tenant provisioning credential, its first domain, first subscription, and
first member. The tenant credential creates additional domains and can rotate
without exposing its replacement secret. Domain-administration credentials
cannot create domains. These IDs remain opaque routing scopes, not account or
Shared Space membership.

Current relay limits are 16 MiB of decoded ciphertext per message, 256 MiB per
encrypted blob, 100 messages per fetch page, and a 25-second maximum wake wait.
Domains receive 10,000 messages/1 GiB message bytes and 10,000 blobs/1 GiB
blob bytes. Tenants receive 256 domains, 1,000,000 messages/1 TiB message
bytes, and 1,000,000 blobs/1 TiB blob bytes. Authority limits are 256 active
and 4,096 retained members; 64 outstanding and 4,096 retained admissions; 256
credential rotations per subject and 4,096 per domain. Terminal admissions
have a 30-day exact-retry window and are collected in batches of at most 256.

## Development

Requirements are Go 1.26 or newer and PostgreSQL 17 or newer.

```sh
go test ./...
go vet ./...
```

To exercise the PostgreSQL integration suite, set a disposable database URL:

```sh
FACETS_NODE_TEST_DATABASE_URL='postgres://facets:facets@localhost:5432/facets?sslmode=disable' go test ./...
```

## Running with Compose

```sh
cp .env.example .env
# Replace the placeholder with a unique value, for example: openssl rand -hex 32
install -d -m 700 deploy/tls
# Install a certificate and key for the public hostname as:
# deploy/tls/server.crt and deploy/tls/server.key
REV=$(git rev-parse --verify HEAD)
TREE=$(git rev-parse --verify 'HEAD^{tree}')
FACETS_NODE_SOURCE_REVISION="$REV" \
FACETS_NODE_SOURCE_TREE="$TREE" \
  docker compose build
docker compose up --no-build
test "$(docker image inspect facets-node-node:latest \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "org.opencontainers.image.source-tree"}}')" = \
  "$REV $TREE"
test "$(docker image inspect facets-node-node:latest --format '{{.Id}}')" = \
  "$(docker inspect facets-node-node-1 --format '{{.Image}}')"
```

The two source values are embedded as OCI labels on the final Node image. For a
source-copy deployment without `.git`, derive them from the committed source
repository and pass them explicitly to the remote build. Do not put them in
`.env`, where they can silently become stale. Before accepting a deployment,
inspect `org.opencontainers.image.revision` and
`org.opencontainers.image.source-tree` on both the built image and the image ID
used by the running Node container. Development builds may omit the values and
are labeled `unknown`; such an image is not a revision-attested deployment.

The Node listener is published only on `127.0.0.1:8080`. It is the private
management ingress for `/livez`, `/readyz`, `/metrics`, and operator
`POST /v1/relay/tenants`, as well as a local diagnostic path to application
routes. Reach it remotely only through an authenticated management tunnel.

Caddy publishes HTTPS on port 8443 and forwards only `/v1/pairing/*` and
`/v1/relay/tenants/*`. Requests for operator provisioning, operations
endpoints, or any unknown path receive `404` at Caddy and never reach the Node.
The installed certificate must validate the hostname or IP clients use; never
disable certificate verification or expose the plaintext Node port. The
Compose stack refuses to start until `FACETS_NODE_POSTGRES_PASSWORD` is supplied
in the ignored `.env` file; never reuse that database credential for any Node
or external service.

Compose persists PostgreSQL metadata and opaque blob bytes in separate named
volumes. A valid backup/restore or host migration must treat both volumes as one
checkpoint. The filesystem blob adapter is the self-hosted checkpoint; hosted
multi-instance deployment still requires the same narrow content-store
interface to be backed by reviewed object storage.

The operations bundle can create an encrypted, coordinated Restic checkpoint
and restore it only into a fresh Compose project. See
[docs/backup-and-restore.md](docs/backup-and-restore.md). Keep the repository
and its separate password off the Node host for actual disaster recovery.
Source-copy deployments must pass the same committed revision to
`backup-checkpoint.sh`; the script validates an explicit value and records it in
the checkpoint manifest instead of replacing it with an unavailable local Git
revision.

## Security boundary

Pairing, tenant-provisioning, relay-member-admission, relay-member,
relay-administration, and operator bearer tokens are independent high-entropy secrets. Send bearer
credentials only in the `Authorization` header over TLS; the one exception is
the client-generated relay credentials inside the retry-safe, TLS-protected
operator provisioning request. Facets Node does not log authorization headers,
request bodies, ciphertext, or client IP addresses. See
[SECURITY.md](SECURITY.md) for reporting and deployment requirements, and
[docs/replica-relay-api.md](docs/replica-relay-api.md) for the relay contract.

## Verification status

The ordinary Go suite covers in-memory protocol behavior, cross-language
fixtures, HTTP authorization, and the checked-in Caddy exposure policy. Tests
that set `FACETS_NODE_TEST_DATABASE_URL` exercise a real disposable PostgreSQL
store, including tenant/domain provisioning, subscription exact retries,
subscription-level delivery, and split quota counters across pool restarts.
Tests that set
`FACETS_NODE_TEST_BASE_URL` and `FACETS_NODE_TEST_OPERATOR_TOKEN` exercise the
running HTTP/PostgreSQL/filesystem stack, including a pre-existing-message wake
fallback that does not depend on an in-process notification. These opt-in gates
are skipped, not simulated, when their environment is absent. Compose/Proxmox,
restart, and backup/restore results document specific prior checkpoints; they
must be rerun before claiming the current image has passed those deployment
gates.

## License

Apache License 2.0.
