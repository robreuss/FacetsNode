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
FACETS_NODE_TEST_DATABASE_URL='postgres://facets:<password>@postgres:5432/facets?sslmode=disable' \
  go test ./internal/postgres \
    -run 'TestPostgres(StorePersistsOpaqueMailbox|RelayPersistsSequences)' -v

FACETS_NODE_TEST_BASE_URL='http://node:8080' \
FACETS_NODE_TEST_OPERATOR_TOKEN='<same operator value from .env>' \
  go test ./integration -run 'TestLive(Pairing|ReplicaRelay)' -v
```

Run these from an ephemeral Go container attached to the corresponding Compose
network, or through a development tunnel. The Proxmox gate also tears down both
containers without deleting the named volume, starts the same image again,
verifies pairing routes and replica domains/messages remain, and confirms
`/readyz`. Never add `--volumes` to this persistence check.

## What this checkpoint does not prove

- public internet safety or production TLS;
- multi-tenant account admission and distributed abuse controls;
- encrypted backup, restore to a fresh VM, or point-in-time recovery;
- rolling upgrade or schema downgrade behavior;
- Sync blobs, checkpoints, retention collection, or Shared Space policy;
- hosted scaling, regional placement, billing, or service-level objectives.

Those are explicit later gates, not properties inferred from a healthy local
Compose stack.
