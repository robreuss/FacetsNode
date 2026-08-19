# Facets Servers

This repository contains the shared Go foundation for two independently
deployed Facets services:

| Service | Executable / image target | Compose application | Configuration prefix |
| --- | --- | --- | --- |
| Facets Device Sync Server | `facets-device-sync-server` / `device-sync` | `compose.yaml` | `FACETS_DEVICE_SYNC_` |
| Facets Shared Spaces Server | `facets-shared-spaces-server` / `shared-spaces` | `deploy/shared-spaces/compose.yaml` | `FACETS_SHARED_SPACES_` |

The services share opaque envelope routing, PostgreSQL persistence, encrypted
blob custody, cursors, receipts, checkpoints, wake hints, quotas, audit facts,
and storage interfaces. They do not share a deployment lifecycle, database
credentials, database namespace, blob namespace, quotas, or authority data.
Installing one service does not expose the other product.

The currently implemented server foundation is content-blind. It stores opaque
routing identifiers, capability digests, bounded metadata, client-encrypted
envelopes, and encrypted blobs. It does not parse FEF, principal, Persona,
device, or Space semantics and never receives a domain content key. The
Device Sync executable additionally exposes the first product-level account
bootstrap boundary: an operator-issued, one-time admission atomically creates
an isolated Device Sync principal, relay tenant, protected control domain, and
initial device. It can enroll additional devices, provision opaque per-Space
domains, report a content-blind transport inventory, and atomically revoke a
device from its control and Space memberships. The Shared Spaces executable
implements the first product authority boundary: an operator provisions an
isolated Space and initial host, the host issues bounded participant
invitations, invitees claim relay membership, and the host can inspect or
revoke participants atomically. Every accepted Shared Space authority change
also appends a content-blind, cursor-paged administrative audit event in the
same PostgreSQL transaction.

## Implemented shared foundation

- PostgreSQL-backed, restart-safe opaque message delivery
- Tenant, domain, subscription, and delivery-member scopes
- Client-generated bearer capabilities stored only as domain-separated digests
- Exact-retry idempotence and collision rejection
- At-least-once cursor delivery with monotonic accepted/applied receipts
- Disposable wake hints backed by authoritative polling
- Per-domain and per-tenant message/blob quotas
- Resumable content-addressed encrypted blob uploads
- Opaque checkpoint fences, staging, activation, and bounded collection
- Fixed-surface traffic controls, redacted structured logs, health, and metrics
- Independent coordinated PostgreSQL/blob backup and fresh-project restore for
  Device Sync and Shared Spaces
- Cross-language Swift/Go transport fixtures

Current relay limits are 16 MiB of decoded ciphertext per message, 256 MiB per
encrypted blob, 100 messages per fetch page, and a 25-second maximum wake wait.
See [the data-plane contract](docs/replica-relay-api.md) for the complete limits
and authority model.

The initial Device Sync account bootstrap is specified in
[the Device Sync bootstrap contract](docs/device-sync-bootstrap.md). The
bootstrap authorizes service use and relay scopes only. Device-generated
content keys never pass through the operator credential or account admission.

The first Shared Spaces authority lifecycle is specified in
[the Shared Spaces bootstrap contract](docs/shared-spaces-bootstrap.md).
Immutable interaction modes and participant roles derive relay operations.
For E2EE Spaces, the service atomically stores participant-specific encrypted
key grants and advances key epochs on revocation, but plaintext content keys
remain a client concern and never pass through the Shared Spaces operator
credential. Authenticated participants can recover their own current role,
derived capabilities, key epoch, and bootstrap readiness after relaunch without
receiving the Space roster or using a Space administration credential.

## Development

Requirements are Go 1.26 or newer and PostgreSQL 17 or newer.

```sh
go test ./...
go vet ./...
```

The disposable PostgreSQL and live-stack integration gates are opt-in and
skipped rather than simulated when their explicit test environment is absent.

## Run Facets Device Sync Server

```sh
cp .env.example .env
# Set a long independent PostgreSQL password.
# Generate the operator token with:
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'

install -d -m 700 deploy/tls
# Install deploy/tls/server.crt and deploy/tls/server.key.

REV=$(git rev-parse --verify HEAD)
TREE=$(git rev-parse --verify 'HEAD^{tree}')
FACETS_SERVER_SOURCE_REVISION="$REV" \
FACETS_SERVER_SOURCE_TREE="$TREE" \
  docker compose build
docker compose up --no-build -d
curl --fail http://127.0.0.1:8080/readyz
docker compose exec -T server \
  /facets-device-sync-server issue-account-admission
```

The private management listener is published only on loopback. Caddy publishes
the reviewed application allowlist, including Device Sync admission claims and
authenticated principal operations, over HTTPS on port 8443. Operator admission
issuance remains private. Never expose the
plaintext management port or disable certificate verification.

## Run Facets Shared Spaces Server

```sh
cp deploy/shared-spaces/.env.example deploy/shared-spaces/.env
# Set independent Shared Spaces PostgreSQL and operator secrets.

REV=$(git rev-parse --verify HEAD)
TREE=$(git rev-parse --verify 'HEAD^{tree}')
FACETS_SERVER_SOURCE_REVISION="$REV" \
FACETS_SERVER_SOURCE_TREE="$TREE" \
  docker compose --env-file deploy/shared-spaces/.env \
    -f deploy/shared-spaces/compose.yaml build
docker compose --env-file deploy/shared-spaces/.env \
  -f deploy/shared-spaces/compose.yaml up --no-build -d
curl --fail http://127.0.0.1:8081/readyz
```

Shared Spaces uses its own PostgreSQL and blob volumes. Running both Compose
applications on one host is supported, but they remain separate services with
no cross-service table joins or replicated membership database. Exact Space
provisioning is operator-authorized and remains on the loopback management
listener. Participant invitation claims, authenticated Space status, and
participant administration are available through the reviewed HTTPS
application allowlist on port 9443.

## Configuration and provenance

Every service rejects the other service's environment prefix. There is no
legacy `FACETS_NODE_` configuration fallback. Traffic controls use the chosen
service prefix followed by
`TRAFFIC_<SURFACE>_{RATE_PER_MINUTE,BURST,CONNECTION_RATE_PER_MINUTE,CONNECTION_BURST,CONCURRENCY}`.

`FACETS_SERVER_SOURCE_REVISION` and `FACETS_SERVER_SOURCE_TREE` are OCI build
arguments shared by both images. A revision-attested deployment supplies full
lowercase 40-character values and verifies the resulting immutable image
labels and running image ID. Development builds may use `unknown`, but that
does not pass the deployment gate.

## Backup and restore

Each service has an independent operations profile because PostgreSQL metadata
and opaque blob bytes form a service-specific recovery unit. The scripts create
encrypted Restic checkpoints and restore only into fresh Compose projects. See
[Device Sync backup and restore](docs/backup-and-restore.md) and
[Shared Spaces backup and restore](docs/shared-spaces-backup-and-restore.md).

## Security boundary

Operator, tenant-provisioning, relay-administration, admission, and member
credentials are independent high-entropy secrets. Send bearer credentials only
in the `Authorization` header over TLS. The server does not log authorization
headers, request bodies, ciphertext, bearer values, or client IP addresses.
See [SECURITY.md](SECURITY.md) for reporting and deployment requirements.

FEF remains the semantic interchange format inside encrypted payloads; it is
not a transport, authority, or billing record. No valid FEF, device grant,
payment record, or Shared Space membership implicitly authorizes compute.

## Verification boundary

The ordinary Go suite covers protocol behavior, cross-language fixtures, HTTP
authorization, traffic/metric bounds, service-specific configuration, and the
checked-in ingress policy. YAML parsing and shell syntax can be checked without
Docker. Compose execution, restart, and backup/restore are separate runtime
gates and must be rerun for the exact image before making deployment claims.

## License

Apache License 2.0.
