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
chmod 600 .env
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

The API binds only to the VM's loopback interface. For development from another
machine, use an SSH tunnel rather than opening a LAN or public firewall rule:

```sh
ssh -L 18080:127.0.0.1:8080 <vm-user>@<vm-address>
```

The tunneled endpoint is then `http://127.0.0.1:18080`. This is a development
transport only. A hosted or remotely accessed Node requires a reviewed TLS
reverse proxy, admission and distributed rate limits, restricted operations
endpoints, monitoring, and incident procedures.

## Verification

The persistent integration gate is:

```sh
# One-time disposable integration database:
docker compose exec postgres createdb -U facets facets_test

FACETS_NODE_TEST_DATABASE_URL='postgres://facets:<password>@postgres:5432/facets_test?sslmode=disable' \
  go test ./internal/postgres \
    -run 'TestPostgres(StorePersistsOpaqueMailbox|Relay(PersistsSequences|SerializesOutstandingAdmissionLimit))' -v

FACETS_NODE_TEST_BASE_URL='http://node:8080' \
FACETS_NODE_TEST_OPERATOR_TOKEN='<same operator value from .env>' \
  go test ./integration -run 'TestLive(Pairing|ReplicaRelay)' -v
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

## What this checkpoint does not prove

- public internet safety or production TLS;
- multi-tenant account admission and distributed abuse controls;
- restore to a fresh VM, periodic off-host recovery drills, or point-in-time
  recovery;
- rolling upgrade or schema downgrade behavior;
- resumable blob upload, checkpoints, retention/orphan collection, or Shared
  Space policy;
- hosted scaling, regional placement, billing, or service-level objectives.

Those are explicit later gates, not properties inferred from a healthy local
Compose stack.
