# Proxmox development deployment

The canonical persistent development profile is a dedicated Ubuntu 24.04 VM,
not the Proxmox host and not a Facets Worker machine. The first validated size
is 2 host CPU cores, 4 GiB RAM, and a 32 GiB ZFS-backed system disk. The VM uses
DHCP, the QEMU guest agent, Docker Engine, and Docker Compose v2. Automatic boot
remains disabled until backup, upgrade, and recovery policies are proven.

## Install and launch

Copy the repository to the VM, then create the uncommitted environment file:

```sh
cp .env.example .env
openssl rand -hex 32
# Put that output after FACETS_NODE_POSTGRES_PASSWORD= in .env.
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
# Put this separate value after FACETS_NODE_OPERATOR_TOKEN= in .env.
install -d -m 700 deploy/tls
# Install the certificate and private key for the public DNS name as
# deploy/tls/server.crt and deploy/tls/server.key.
chmod 600 .env
REV=<40-character-committed-revision>
TREE=<40-character-committed-tree>
FACETS_NODE_SOURCE_REVISION="$REV" \
FACETS_NODE_SOURCE_TREE="$TREE" \
  docker compose build
docker compose up --no-build -d
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

Derive both source values in the canonical repository before copying its
committed tree to this VM:

```sh
REV=$(git rev-parse --verify HEAD)
TREE=$(git rev-parse --verify 'HEAD^{tree}')
printf 'revision=%s tree=%s\n' "$REV" "$TREE"
```

The VM's deployment directory may intentionally be a source copy without
`.git`; do not create a mutable revision marker that can drift from its bytes.
Instead, checksum-compare the copied tree to a `git archive` of that commit,
pass the two values to the build, and verify the immutable image labels plus
the running container image ID:

```sh
test "$(docker image inspect facets-node-node:latest \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "org.opencontainers.image.source-tree"}}')" = \
  "$REV $TREE"
test "$(docker image inspect facets-node-node:latest --format '{{.Id}}')" = \
  "$(docker inspect facets-node-node-1 --format '{{.Image}}')"
```

An `unknown` label is acceptable for local iteration but fails the persistent
deployment gate.

The plaintext Node API binds only to the VM's loopback interface. It is the
private management ingress, including readiness, metrics, and operator domain
provisioning. For development from another machine, use an SSH tunnel rather
than opening a LAN or public firewall rule:

```sh
ssh -L 18080:127.0.0.1:8080 <vm-user>@<vm-address>
```

The tunneled endpoint is then `http://127.0.0.1:18080`. This is a development
transport only. Caddy separately publishes HTTPS on port 8443. It forwards
only `/v1/pairing/*` and `/v1/relay/tenants/*`; operations and operator
provisioning return `404`. The certificate must validate the client-visible
host name. This route separation is necessary but does not by itself prove
public-internet readiness; account admission, distributed rate limits,
monitoring, independent review, and incident procedures remain open gates.

## Verification

The persistent integration gate is:

```sh
# One-time disposable integration database:
docker compose exec postgres createdb -U facets facets_test

FACETS_NODE_TEST_DATABASE_URL='postgres://facets:<password>@postgres:5432/facets_test?sslmode=disable' \
  go test ./internal/postgres \
    -run 'TestPostgres(StorePersistsOpaqueMailbox|Relay(PersistsSequences|TenantProvisioning|SerializesOutstandingAdmissionLimit)|SubscriptionExactRetry)' -v

FACETS_NODE_TEST_BASE_URL='http://node:8080' \
FACETS_NODE_TEST_OPERATOR_TOKEN='<same operator value from .env>' \
  go test ./integration -run 'TestLive(Pairing|ReplicaRelay)' -v

# Use the CA required by the installed certificate; never use curl -k.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert <ca-file> https://<node-name>:8443/v1/pairing/routes \
  -X POST -H 'Content-Type: application/json' -d '{}')" = 400
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert <ca-file> https://<node-name>:8443/readyz)" = 404
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --cacert <ca-file> https://<node-name>:8443/v1/relay/tenants -X POST)" = 404
```

Run these from an ephemeral Go container attached to the corresponding Compose
network, or through a development tunnel. `facets_test` is disposable; the
PostgreSQL suite truncates its relay tables and must never target the running
service database. The Proxmox gate also tears down both
containers without deleting the named volume, starts the same image again,
verifies pairing routes plus replica domains/messages/blob metadata remain, and
confirms `/readyz`. The same checkpoint records the sorted SHA-256 digest list
from every regular file in the `facets-node-blobs` volume before and after
recreation and requires an exact match. Never add `--volumes` to this
persistence check.

The live replica pattern includes the delivery-matrix harness. It publishes
client timestamps out of order, retries exact messages, replays a cursor after
simulated response loss, introduces a delayed wave, publishes concurrently,
and verifies gapless server sequences plus independent recipient catch-up and
acknowledgments. It also truncates an upload mid-request and requires a full
retry, exact blob retry, and cross-member download to succeed. Restart safety
is a separate compositional gate: the PostgreSQL test closes and recreates its
pool around the same domain, while the Proxmox recreation check preserves both
the database and exact blob-volume digest set.

The live authority-lifecycle harness rotates both administration and member
credentials, proves old/new exact retries after simulated response loss,
rejects old credentials for ordinary operations, rejects prior-secret reuse,
and exercises admission collection. The PostgreSQL gate additionally proves
rotation records across a pool restart and serializes concurrent admission
issuance at the domain limit.

The tenant-provisioning PostgreSQL gate closes and recreates its pool between
initial and additional domain creation, proves exact retry after another
restart, and rejects the wrong tenant secret. The live provisioning/wake gate
creates a child domain through HTTP, retries it, publishes before starting the wake request,
and requires the wake endpoint to find the already-durable PostgreSQL message
without relying on a process-local signal. These tests are skipped when their
explicit disposable-database or live-service environment is absent.

PostgreSQL metadata and the blob volume are one recovery unit. A backup or host
migration that captures only one is incomplete. Direct SQL domain deletion is
not an operational deletion workflow: filesystem orphan collection and a
coordinated deletion command are still pending.

The coordinated recovery gate uses the checked-in operations Compose file and
scripts documented in [backup-and-restore.md](backup-and-restore.md). The first
Proxmox proof stopped the Node writer, encrypted one PostgreSQL dump plus the
exact blob tree into a Restic snapshot, and restored it into a different
Compose project and fresh named volumes on another loopback port. All relay
table counts, blob paths and digests, and both `/readyz` results matched. This
same-host proof does not replace an off-host repository, fresh-VM drill, or a
documented retention schedule.

The authority-lifecycle deployment repeated that isolated restore after
credential rotations were present. Source and recovery matched rotation,
admission, and audit counts, both services became ready, and the temporary
recovery stack and test repository were removed afterward.

For a source-copy deployment, create the checkpoint with the same value shown
by the running image label:

```sh
FACETS_NODE_CHECKPOINT_REVISION=<40-character-committed-revision> \
  ./scripts/backup-checkpoint.sh \
  /absolute/off-host-restic-repository \
  /absolute/protected-restic-password-file
```

The script rejects empty, abbreviated, uppercase, `unknown`, or otherwise
malformed caller-supplied revisions. When the variable is not supplied it uses
the current Git commit when available, otherwise records `unknown`.

## What this checkpoint does not prove

- public internet safety or independent production TLS review (the checked-in
  HTTPS route-separation policy is tested, but is only one boundary);
- multi-tenant account admission and distributed abuse controls;
- restore to a fresh VM, periodic off-host recovery drills, or point-in-time
  recovery;
- rolling upgrade or schema downgrade behavior;
- resumable blob upload, checkpoints, retention/orphan collection, or Shared
  Space policy;
- hosted scaling, regional placement, billing, or service-level objectives.

Those are explicit later gates, not properties inferred from a healthy local
Compose stack.
