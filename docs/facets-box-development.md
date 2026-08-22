# Facets Box development host

This document records the first container-host baseline for converging the
Facets services toward a Facets Box. It is a development deployment, not a
claim that the Facets Box control plane, hardware profile, production ingress,
or sealed-compute boundary is implemented.

## Capability boundaries

The development Box is a dedicated Ubuntu VM. It is not the Proxmox host and
not a Facets Distributed AI Worker. Facets Device Sync and Shared Spaces each
run their own Server, PostgreSQL, and Caddy containers. Future Worker, Tor
ingress, and control-plane containers must keep their own identities, secrets,
storage, and network authority. A workload must not receive the Docker socket,
Proxmox credentials, another workload's environment file, or another
workload's data volume.

The first validated host is Proxmox VM 190, `facets-box-dev`:

- Ubuntu 24.04, four host CPU cores, 8 GiB RAM, and a 64 GiB ZFS-backed disk;
- DHCP with the QEMU guest agent, Docker Engine, and Docker Compose v2;
- automatic boot disabled while upgrade, off-host backup, and recovery policy
  remain development gates;
- current development lease `192.168.86.44`, retained Device Sync service
  address `192.168.86.62`, Device Sync HTTPS port `8443`, and Shared Spaces
  HTTPS port `9443`.

VM 180, `facets-node-dev`, is the stopped rollback host. Do not delete it until
the new host has survived the next planned upgrade and an off-host recovery
drill. GPU Worker VMs remain independent.

## Immutable release layout

The VM keeps committed source bytes separate from mutable authority:

```text
/srv/facets-box/
  current -> releases/<full Git revision>
  releases/<full Git revision>/
  secrets/device-sync.env
  secrets/device-sync-restic-password
  secrets/shared-spaces.env
  secrets/shared-spaces-test.env
  secrets/restic-password
  tls/device-sync/{server.crt,server.key}
  tls/shared-spaces/{ca.crt,ca.key,server.crt,server.key}
  backups/device-sync-migration-restic/
  backups/shared-spaces-restic/
```

Each release is copied from `git archive` for one committed revision, owned by
root, and passed its exact revision and tree IDs at image build time. The
release's untracked `.env` and `deploy/shared-spaces/.env` are symlinks to the
corresponding protected stable environment files.
`FACETS_DEVICE_SYNC_TLS_DIRECTORY` and
`FACETS_SHARED_SPACES_TLS_DIRECTORY` point each Caddy instance at its separate
stable TLS directory. Secrets, private keys, and Restic credentials never enter
the release archive or Git.

The current certificate is signed by a development-only local CA and covers
the VM hostname and current IP address. Clients must trust that CA explicitly;
do not disable certificate verification. A stable DNS name and independently
managed certificate are required before non-development ingress.

## Network boundary

Device Sync management binds only to VM loopback on port `18080`; Shared Spaces
management and exact Space provisioning bind only to VM loopback on port
`8081`. Their separate Caddy instances publish reviewed application-path
allowlists on HTTPS ports `8443` and `9443`. PostgreSQL is reachable only on
each capability's Compose internal network. The build/test cache reaches an
egress-capable network only while dependencies are primed; PostgreSQL-backed
tests run on the internal network with `GOPROXY=off`.

Caddy is the HTTP reverse proxy in this deployment. The repository's Apache
License 2.0 is a software license and does not imply use of Apache HTTP Server.

## Shared Spaces validated checkpoint

On 2026-08-21, committed revision
`60f1fb8556429074425c7aa49ef9b6985bccc883` and source tree
`fc38d6284a936d01fc1d92082f1c5ac6a2fc3a12` passed these gates on VM 190:

- the image build ran the complete ordinary Go suite;
- the complete `internal/postgres` suite passed against fresh PostgreSQL 17;
- `TestLiveSharedSpacesVerticalSlice` passed against the running service,
  including additional-device enrollment and individual-device revocation;
- the OCI revision and tree labels matched the running container image ID;
- Caddy served trusted development HTTPS while management routes remained
  outside its allowlist;
- removing and recreating every canonical container without deleting named
  volumes preserved 4 Spaces, 8 participants, 12 participant devices,
  24 authority events, and 8 relay messages;
- an encrypted coordinated PostgreSQL/blob checkpoint passed `restic check`,
  restored into a fresh Compose project, matched all five counts, and served
  readiness from both source and recovery instances;
- a live Proxmox snapshot backup was written to `local-recovery` and the
  Shared Spaces service remained healthy after the guest filesystem freeze.

The temporary recovery containers, networks, and recovery volumes were removed
after comparison. The encrypted checkpoint and canonical service volumes were
retained. This is a same-host recovery proof only. Off-host retention, a
fresh-VM restore, DNS/TLS operations, monitoring, incident procedures, and
public-internet review remain open deployment gates.

## Device Sync migration checkpoint

On 2026-08-21, Device Sync was migrated from VM 180 to VM 190 while retaining
its client-visible `https://192.168.86.62:8443` endpoint and pinned development
certificate. VM 190 carries `192.168.86.62` as a persistent secondary service
address; VM 180 remains powered off as the rollback host.

Committed revision `3fcf53a4fd7f4e1828ff6dd1c59ab132b09694ab` and source
tree `eea5455bf0467027c1d7a9d81ae0316997bf0852` passed these gates:

- an encrypted checkpoint of the VM 180 service passed `restic check` and
  restored into an isolated project before cutover;
- the migrated PostgreSQL database retained 2 principals, 5 devices, 2 Spaces,
  2 relay tenants, 4 relay domains, and 6 relay messages;
- both regular blob files retained their original paths and SHA-256 digest;
- the complete ordinary Go suite, a focused PostgreSQL suite, and the live
  pairing, relay, and Device Sync vertical slices passed;
- the FacetsNodeClient Swift-to-Go live enrollment gate completed against an
  isolated restore of the migrated service;
- migration 040 corrected the previously unembedded enrollment-mailbox schema,
  and the locked sponsor lookup was exercised against real PostgreSQL;
- the public Caddy allowlist admits both candidate enrollment-mailbox routes
  while readiness and operator provisioning remain hidden;
- the certificate fingerprint and SANs match the prior deployment, and the
  running image revision and tree labels match the release;
- removing and recreating the canonical containers without deleting named
  volumes preserved the authority, relay, migration, and blob state;
- post-migration Restic snapshot `1b82851c` passed repository checking and an
  isolated restore comparison, after which the temporary recovery projects and
  volumes were removed;
- Proxmox snapshot backup
  `vzdump-qemu-190-2026_08_21-20_58_13.vma.zst` completed after a guest
  filesystem freeze, and both Node services remained healthy.

This proves the server migration and same-host recovery path. It does not prove
the Facets physical-device enrollment or multi-device synchronization flows;
those remain client acceptance work.

## Checkpoint and isolated restore

Run a checkpoint from the active release with the revision carried by the
running image:

```sh
cd /srv/facets-box/current
FACETS_SHARED_SPACES_CHECKPOINT_REVISION=<full-running-image-revision> \
  sudo ./deploy/shared-spaces/scripts/backup-checkpoint.sh \
  /srv/facets-box/backups/shared-spaces-restic \
  /srv/facets-box/secrets/restic-password
```

Restore only into a new project and a separate loopback port:

```sh
cd /srv/facets-box/current
sudo ./deploy/shared-spaces/scripts/restore-checkpoint.sh \
  /srv/facets-box/backups/shared-spaces-restic \
  /srv/facets-box/secrets/restic-password \
  facets-shared-spaces-recovery-YYYYMMDD \
  18082
```

Compare authority and relay counts, blob paths and digests, key-grant access,
and readiness before removing that explicitly named recovery project. Never
use the canonical project as a restore target.

For Device Sync, use the separate checkpoint authority and restore only into a
new project and unused loopback port:

```sh
cd /srv/facets-box/current
sudo ./scripts/backup-checkpoint.sh \
  /srv/facets-box/backups/device-sync-migration-restic \
  /srv/facets-box/secrets/device-sync-restic-password

sudo ./scripts/restore-checkpoint.sh \
  /srv/facets-box/backups/device-sync-migration-restic \
  /srv/facets-box/secrets/device-sync-restic-password \
  facets-device-sync-recovery-YYYYMMDD \
  18082
```
