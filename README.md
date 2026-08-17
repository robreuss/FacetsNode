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
- Fixed-surface per-process identity, connection-aggregate, and concurrency
  limits with bounded private metrics
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
- Disposable PostgreSQL `LISTEN`/`NOTIFY` domain-change hints across Node
  instances that accelerate, but never replace, cursor polling
- Separate per-domain and tenant-wide message/blob count and byte quotas
- Server-timed checkpoint write fences, opaque staging, administrator activation, custody-gated dry-run,
  and exact-retry bounded message/blob collection with latest-two retention
- PostgreSQL-backed concurrent publication with restart-safe ordering
- Live delivery-matrix proof for cursor replay, delayed and concurrent traffic,
  independent recipients, acknowledgment progression, and interrupted uploads
- Cross-language tests against the public Swift replica-carrier fixture
- Domain-scoped, content-addressed encrypted-blob storage on a separate volume
- Restart-safe contiguous blob uploads with chunk and final digest verification,
  plus Range-capable GET/HEAD

Hosted object storage/account admission, Shared Space membership, billing, and
compute are later modules. Relay member admission grants routing authority only; it does
not verify identity or carry a domain content key. Checkpoint data remains
opaque and collection requires explicit domain administration. No valid FEF,
device grant, payment record, or Shared Space membership will implicitly grant
compute execution.

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
Open uploads reserve their final blob count and byte count, expire after seven
days without progress by default, and are physically reconciled only after the
configured orphan grace period.

### Traffic controls

Every registered route belongs to one of five fixed surfaces. Limits are
process-local; a hosted multi-instance edge still needs coordinated distributed
abuse controls. The defaults are:

| Surface suffix | Identity rate/burst | Connection rate/burst | Concurrency |
| --- | ---: | ---: | ---: |
| `RENDEZVOUS` | 300/min, 100 | 2,400/min, 400 | 32 |
| `RELAY_MESSAGE` | 3,000/min, 500 | 24,000/min, 2,000 | 128 |
| `STORAGE` | 1,200/min, 200 | 4,800/min, 800 | 32 |
| `CHECKPOINT_ADMIN` | 600/min, 200 | 4,800/min, 800 | 32 |
| `MANAGEMENT` | 300/min, 100 | 600/min, 200 | 8 |

Override a value with
`FACETS_NODE_TRAFFIC_<SURFACE>_RATE_PER_MINUTE`, `_BURST`,
`_CONNECTION_RATE_PER_MINUTE`, `_CONNECTION_BURST`, or `_CONCURRENCY`.
Rates are capped at 60,000/min, bursts at 10,000, and concurrency at 1,024.
Each surface has separate fixed-capacity identity and connection-address LRU
tables of at most 2,048 SHA-256 keys; idle entries expire after 15 minutes.
Bearer credentials are hashed before lookup and never retained. Requests with
no bearer use a canonical route scope plus the direct connection address, and
an additional connection-address bucket bounds churn from random credentials
or route IDs. Forwarding headers are not trusted. A bounded request returns
`429` with an integer `Retry-After`; an exact retry remains valid after refill.

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
fixtures, HTTP authorization, bounded traffic/metric surfaces, and the
checked-in Caddy exposure policy. Tests
that set `FACETS_NODE_TEST_DATABASE_URL` exercise a real disposable PostgreSQL
store, including tenant/domain provisioning, subscription exact retries,
subscription-level delivery, split quota counters across pool restarts,
checkpoint activation/collection under concurrent publication, and a
two-instance wake listener with a missed-notification fetch fallback.
Tests that set
`FACETS_NODE_TEST_BASE_URL` and `FACETS_NODE_TEST_OPERATOR_TOKEN` exercise the
running HTTP/PostgreSQL/filesystem stack, including a pre-existing-message wake
fallback that does not depend on an in-process notification. These opt-in gates
are skipped, not simulated, when their environment is absent. Compose/Proxmox,
restart, and backup/restore results document specific prior checkpoints; they
must be rerun before claiming the current image has passed those deployment
gates.

The separate
[high-volume checkpoint/restart gate](docs/high-volume-restart-acceptance.md)
publishes and custody-acknowledges more than 10,000 messages, performs fenced
multi-batch collection and replacement-subscription bootstrap, then verifies
continued delivery after container recreation without reprovisioning. It is
disabled unless `FACETS_NODE_TEST_HIGH_VOLUME=1` and an explicit external
mode-0600 state path are supplied; no current deployment result is implied by
its presence in the repository.

## License

Apache License 2.0.
